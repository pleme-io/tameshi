//! TTL-based caching for layer collectors.
//!
//! Wraps any [`LayerCollector`] with an in-memory cache that returns
//! cached results within the TTL window, avoiding repeated expensive
//! collection operations (Nix store walks, OCI pulls, etc.).

use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::collectors::traits::LayerCollector;
use crate::error::Result;
use crate::signature::{LayerSignature, LayerType};

/// Cache performance statistics.
#[derive(Clone, Debug, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub invalidations: u64,
}

impl CacheStats {
    /// Hit rate as a percentage (0.0 to 100.0).
    #[inline]
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { (self.hits as f64 / total as f64) * 100.0 }
    }
}

/// A cached layer collector that wraps an inner collector with TTL-based caching.
pub struct CachedCollector<C: LayerCollector> {
    inner: C,
    cache: RwLock<Option<CacheEntry>>,
    ttl: Duration,
    stats: RwLock<CacheStats>,
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
            cache: RwLock::new(None),
            ttl,
            stats: RwLock::new(CacheStats::default()),
        }
    }

    /// Invalidate the cache, forcing the next collect() to hit the inner collector.
    #[inline]
    pub fn invalidate(&self) {
        *self.cache.write().expect("cache lock poisoned") = None;
        self.stats.write().expect("stats lock").invalidations += 1;
    }

    /// Check if the cache currently holds a valid (non-expired) entry.
    #[inline]
    #[must_use]
    pub fn is_cached(&self) -> bool {
        let guard = self.cache.read().expect("cache lock poisoned");
        guard
            .as_ref()
            .is_some_and(|entry| entry.cached_at.elapsed() < self.ttl)
    }

    /// Get a snapshot of cache performance statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        self.stats.read().expect("stats lock").clone()
    }
}

impl<C: LayerCollector> LayerCollector for CachedCollector<C> {
    async fn collect(&self) -> Result<LayerSignature> {
        // Check cache with read lock
        {
            let guard = self.cache.read().expect("cache lock poisoned");
            if let Some(entry) = guard.as_ref() {
                if entry.cached_at.elapsed() < self.ttl {
                    self.stats.write().expect("stats lock").hits += 1;
                    return Ok(entry.signature.clone());
                }
            }
        }

        // Cache miss or expired -- collect from inner
        self.stats.write().expect("stats lock").misses += 1;
        let signature = self.inner.collect().await?;

        // Store in cache with write lock
        {
            let mut guard = self.cache.write().expect("cache lock poisoned");
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

    #[tokio::test]
    async fn cache_stats_hit() {
        let mock = MockCollector::new(LayerType::Nix);
        let cached = CachedCollector::new(mock, Duration::from_secs(60));

        // First call is a miss, second is a hit
        let _ = cached.collect().await.unwrap();
        let _ = cached.collect().await.unwrap();

        let stats = cached.stats();
        assert_eq!(stats.hits, 1);
    }

    #[tokio::test]
    async fn cache_stats_miss() {
        let mock = MockCollector::new(LayerType::Oci);
        let cached = CachedCollector::new(mock, Duration::from_secs(60));

        // First access is always a miss
        let _ = cached.collect().await.unwrap();

        let stats = cached.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);
    }

    #[tokio::test]
    async fn cache_stats_hit_rate() {
        let mock = MockCollector::new(LayerType::Helm);
        let cached = CachedCollector::new(mock, Duration::from_secs(60));

        // 1 miss + 3 hits = 75% hit rate
        let _ = cached.collect().await.unwrap(); // miss
        let _ = cached.collect().await.unwrap(); // hit
        let _ = cached.collect().await.unwrap(); // hit
        let _ = cached.collect().await.unwrap(); // hit

        let stats = cached.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 3);
        let rate = stats.hit_rate();
        assert!((rate - 75.0).abs() < f64::EPSILON, "Expected 75.0, got {rate}");

        // Empty stats should return 0.0
        let empty = CacheStats::default();
        assert!((empty.hit_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn cache_stats_invalidation() {
        let mock = MockCollector::new(LayerType::Tofu);
        let cached = CachedCollector::new(mock, Duration::from_secs(60));

        let _ = cached.collect().await.unwrap();
        cached.invalidate();
        cached.invalidate();

        let stats = cached.stats();
        assert_eq!(stats.invalidations, 2);
    }
}
