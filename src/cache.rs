//! TTL-based caching for layer collectors.
//!
//! Wraps any [`LayerCollector`] with an in-memory cache that returns
//! cached results within the TTL window, avoiding repeated expensive
//! collection operations (Nix store walks, OCI pulls, etc.).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::collectors::traits::LayerCollector;
use crate::error::Result;
use crate::signature::{LayerSignature, LayerType};

/// A cached layer collector that wraps an inner collector with TTL-based caching.
pub struct CachedCollector<C: LayerCollector> {
    inner: C,
    cache: Mutex<Option<CacheEntry>>,
    ttl: Duration,
}

struct CacheEntry {
    signature: LayerSignature,
    cached_at: Instant,
}

impl<C: LayerCollector> CachedCollector<C> {
    /// Create a new cached collector with the specified TTL.
    pub fn new(inner: C, ttl: Duration) -> Self {
        Self {
            inner,
            cache: Mutex::new(None),
            ttl,
        }
    }

    /// Invalidate the cache, forcing the next collect() to hit the inner collector.
    pub fn invalidate(&self) {
        *self.cache.lock().expect("cache lock poisoned") = None;
    }

    /// Check if the cache currently holds a valid (non-expired) entry.
    #[must_use]
    pub fn is_cached(&self) -> bool {
        let guard = self.cache.lock().expect("cache lock poisoned");
        guard
            .as_ref()
            .is_some_and(|entry| entry.cached_at.elapsed() < self.ttl)
    }
}

impl<C: LayerCollector> LayerCollector for CachedCollector<C> {
    async fn collect(&self) -> Result<LayerSignature> {
        // Check cache
        {
            let guard = self.cache.lock().expect("cache lock poisoned");
            if let Some(entry) = guard.as_ref() {
                if entry.cached_at.elapsed() < self.ttl {
                    return Ok(entry.signature.clone());
                }
            }
        }

        // Cache miss or expired -- collect from inner
        let signature = self.inner.collect().await?;

        // Store in cache
        {
            let mut guard = self.cache.lock().expect("cache lock poisoned");
            *guard = Some(CacheEntry {
                signature: signature.clone(),
                cached_at: Instant::now(),
            });
        }

        Ok(signature)
    }

    fn layer_type(&self) -> LayerType {
        self.inner.layer_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::MockCollector;

    #[tokio::test]
    async fn cache_hit() {
        let mock = MockCollector::new(LayerType::Nix);
        let cached = CachedCollector::new(mock, Duration::from_secs(60));

        let sig1 = cached.collect().await.unwrap();
        assert!(cached.is_cached());
        let sig2 = cached.collect().await.unwrap();
        assert_eq!(sig1.hash, sig2.hash, "Cache should return same signature");
    }

    #[tokio::test]
    async fn cache_invalidate() {
        let mock = MockCollector::new(LayerType::Oci);
        let cached = CachedCollector::new(mock, Duration::from_secs(60));

        let _ = cached.collect().await.unwrap();
        assert!(cached.is_cached());
        cached.invalidate();
        assert!(!cached.is_cached());
    }

    #[tokio::test]
    async fn cache_expires() {
        let mock = MockCollector::new(LayerType::Helm);
        let cached = CachedCollector::new(mock, Duration::from_millis(1));

        let _ = cached.collect().await.unwrap();
        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!cached.is_cached());
    }

    #[test]
    fn cache_layer_type() {
        let mock = MockCollector::new(LayerType::Tofu);
        let cached = CachedCollector::new(mock, Duration::from_secs(60));
        assert_eq!(cached.layer_type(), LayerType::Tofu);
    }

    #[test]
    fn cache_starts_empty() {
        let mock = MockCollector::new(LayerType::Nix);
        let cached = CachedCollector::new(mock, Duration::from_secs(60));
        assert!(!cached.is_cached());
    }
}
