//! Tiered storage for the MerkleLedger.
//!
//! Hot tier: in-memory (last 72 hours, CIRCIA window)
//! Warm tier: S3 Standard (last 90 days)
//! Cold tier: S3 Glacier (2+ years, regulatory retention)

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::ledger::InMemoryLedgerStore;

// =============================================================================
// Storage Tier
// =============================================================================

/// Storage tier for ledger entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageTier {
    /// In-memory, < 72 hours (CIRCIA window).
    Hot,
    /// S3 Standard, < 90 days.
    Warm,
    /// S3 Glacier, 2+ years (regulatory retention).
    Cold,
}

// =============================================================================
// Tiered Storage Configuration
// =============================================================================

/// Configuration for tiered storage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TieredStorageConfig {
    /// Hours before entries move from hot to warm tier (default: 72).
    pub hot_retention_hours: u64,
    /// Days before entries move from warm to cold tier (default: 90).
    pub warm_retention_days: u64,
    /// S3 bucket for warm/cold storage.
    pub s3_bucket: String,
    /// S3 key prefix for ledger data.
    pub s3_prefix: String,
    /// Whether S3 Object Lock (WORM) is enabled.
    pub object_lock_enabled: bool,
}

impl Default for TieredStorageConfig {
    fn default() -> Self {
        Self {
            hot_retention_hours: 72,
            warm_retention_days: 90,
            s3_bucket: "tameshi-ledger".to_string(),
            s3_prefix: "merkle-ledger/".to_string(),
            object_lock_enabled: true,
        }
    }
}

// =============================================================================
// Tier Classification
// =============================================================================

/// Determines which storage tier an entry belongs to based on its age.
///
/// - Hot: younger than `hot_retention_hours`
/// - Warm: younger than `warm_retention_days` but older than hot
/// - Cold: older than `warm_retention_days`
#[must_use]
pub fn classify_tier(
    entry_timestamp: DateTime<Utc>,
    now: DateTime<Utc>,
    config: &TieredStorageConfig,
) -> StorageTier {
    let age = now - entry_timestamp;
    if age < Duration::hours(config.hot_retention_hours as i64) {
        StorageTier::Hot
    } else if age < Duration::days(config.warm_retention_days as i64) {
        StorageTier::Warm
    } else {
        StorageTier::Cold
    }
}

// =============================================================================
// Tiered Ledger Store
// =============================================================================

/// Tiered ledger store that delegates to hot (in-memory) and cold (S3) backends.
///
/// Entries are initially stored in the hot tier (in-memory). When eviction runs,
/// entries older than `hot_retention_hours` are moved to the warm tier. In
/// production the warm/cold tiers use S3 via the `object_store` crate.
pub struct TieredLedgerStore {
    /// Hot tier: in-memory store for recent entries.
    hot: InMemoryLedgerStore,
    /// Tiered storage configuration.
    config: TieredStorageConfig,
    /// Count of entries evicted to warm tier (tracking for tests/metrics).
    warm_evicted: std::sync::Mutex<usize>,
}

impl TieredLedgerStore {
    /// Create a new tiered ledger store with the given configuration.
    #[must_use]
    pub fn new(config: TieredStorageConfig) -> Self {
        Self {
            hot: InMemoryLedgerStore::new(),
            config,
            warm_evicted: std::sync::Mutex::new(0),
        }
    }

    /// Get the tiered storage configuration.
    #[must_use]
    pub fn config(&self) -> &TieredStorageConfig {
        &self.config
    }

    /// Get the hot tier store for direct access (e.g., appending entries).
    #[must_use]
    pub fn hot_store(&self) -> &InMemoryLedgerStore {
        &self.hot
    }

    /// Get entry count in hot tier.
    #[must_use]
    pub fn hot_count(&self) -> usize {
        let entries = self.hot.entries.lock().expect("hot store lock poisoned");
        entries.len()
    }

    /// Get the total number of entries evicted to warm tier.
    #[must_use]
    pub fn warm_evicted_count(&self) -> usize {
        *self
            .warm_evicted
            .lock()
            .expect("warm_evicted lock poisoned")
    }

    /// Evict entries older than `hot_retention_hours` to the warm tier.
    ///
    /// Returns the number of entries evicted. In this implementation,
    /// evicted entries are removed from the hot tier. In production,
    /// they would be written to S3 before removal.
    pub fn evict_to_warm(&self) -> usize {
        self.evict_to_warm_at(Utc::now())
    }

    /// Evict entries older than `hot_retention_hours` relative to the given
    /// timestamp. Used for deterministic testing.
    pub fn evict_to_warm_at(&self, now: DateTime<Utc>) -> usize {
        let cutoff = now - Duration::hours(self.config.hot_retention_hours as i64);

        let mut entries = self.hot.entries.lock().expect("hot store lock poisoned");
        let before = entries.len();
        entries.retain(|e| e.timestamp >= cutoff);
        let evicted = before - entries.len();

        if evicted > 0 {
            let mut warm = self
                .warm_evicted
                .lock()
                .expect("warm_evicted lock poisoned");
            *warm += evicted;
        }

        evicted
    }

    /// Compute storage statistics at the given timestamp.
    #[must_use]
    pub fn stats_at(&self, now: DateTime<Utc>) -> StorageStats {
        let entries = self.hot.entries.lock().expect("hot store lock poisoned");
        let warm_count = *self
            .warm_evicted
            .lock()
            .expect("warm_evicted lock poisoned");

        let mut hot_entries = 0usize;
        let mut oldest_hot: Option<DateTime<Utc>> = None;
        let mut newest_hot: Option<DateTime<Utc>> = None;

        for e in entries.iter() {
            let tier = classify_tier(e.timestamp, now, &self.config);
            if tier == StorageTier::Hot {
                hot_entries += 1;
                match oldest_hot {
                    None => oldest_hot = Some(e.timestamp),
                    Some(t) if e.timestamp < t => oldest_hot = Some(e.timestamp),
                    _ => {}
                }
                match newest_hot {
                    None => newest_hot = Some(e.timestamp),
                    Some(t) if e.timestamp > t => newest_hot = Some(e.timestamp),
                    _ => {}
                }
            }
        }

        StorageStats {
            hot_entries,
            warm_entries: warm_count,
            cold_entries: 0, // cold migration not yet implemented
            total_entries: hot_entries + warm_count,
            oldest_hot,
            newest_hot,
        }
    }

    /// Compute storage statistics using the current time.
    #[must_use]
    pub fn stats(&self) -> StorageStats {
        self.stats_at(Utc::now())
    }
}

// =============================================================================
// Storage Statistics
// =============================================================================

/// Storage statistics for monitoring.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageStats {
    /// Number of entries in the hot tier.
    pub hot_entries: usize,
    /// Number of entries in the warm tier.
    pub warm_entries: usize,
    /// Number of entries in the cold tier.
    pub cold_entries: usize,
    /// Total entries across all tiers.
    pub total_entries: usize,
    /// Timestamp of the oldest entry in the hot tier.
    pub oldest_hot: Option<DateTime<Utc>>,
    /// Timestamp of the newest entry in the hot tier.
    pub newest_hot: Option<DateTime<Utc>>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification_artifact::compose_certification_artifact;
    use crate::forensics::ledger::MerkleLedgerStore;
    use crate::forensics::types::MerkleLedgerEntry;
    use crate::hash::Blake3Hash;
    use crate::signing::{SignedRoot, SigningAlgorithm};

    fn sample_artifact() -> crate::certification_artifact::CertificationArtifact {
        compose_certification_artifact(
            "/usr/bin/app",
            Blake3Hash::digest(b"nix-closure"),
            Blake3Hash::digest(b"kensa-result"),
            Blake3Hash::digest(b"pangea-synthesis"),
            "production",
        )
    }

    fn sample_signed_root() -> SignedRoot {
        SignedRoot {
            root: Blake3Hash::digest(b"root"),
            signature: vec![1, 2, 3, 4],
            algorithm: SigningAlgorithm::Ed25519Local,
            signer_id: "test-signer".to_string(),
            signed_at: Utc::now(),
        }
    }

    fn make_entry_at(ts: DateTime<Utc>) -> MerkleLedgerEntry {
        MerkleLedgerEntry {
            sequence: 0,
            timestamp: ts,
            certification_artifact: sample_artifact(),
            signed_root: sample_signed_root(),
            deployment_context: crate::forensics::types::DeploymentContext {
                cluster: "prod".to_string(),
                namespace: "default".to_string(),
                node: "node-1".to_string(),
                pod: "app-abc".to_string(),
                container: "main".to_string(),
                image_ref: "ghcr.io/pleme-io/app:v1".to_string(),
                binary_paths: vec!["/usr/bin/app".to_string()],
                sdlc_chain_hash: None,
                compliance_report_hash: None,
            },
            entry_hash: Blake3Hash::digest(b"entry"),
            previous_hash: Blake3Hash::from([0u8; 32]),
        }
    }

    // ---- classify_tier tests ----

    #[test]
    fn classify_tier_hot() {
        let config = TieredStorageConfig::default();
        let now = Utc::now();
        let recent = now - Duration::hours(1);
        assert_eq!(classify_tier(recent, now, &config), StorageTier::Hot);
    }

    #[test]
    fn classify_tier_warm() {
        let config = TieredStorageConfig::default();
        let now = Utc::now();
        let days_ago = now - Duration::days(30);
        assert_eq!(classify_tier(days_ago, now, &config), StorageTier::Warm);
    }

    #[test]
    fn classify_tier_cold() {
        let config = TieredStorageConfig::default();
        let now = Utc::now();
        let years_ago = now - Duration::days(365);
        assert_eq!(classify_tier(years_ago, now, &config), StorageTier::Cold);
    }

    #[test]
    fn classify_tier_boundary_at_72h() {
        let config = TieredStorageConfig::default();
        let now = Utc::now();
        // Exactly 72 hours ago should be warm (not hot)
        let exactly_72h = now - Duration::hours(72);
        assert_eq!(classify_tier(exactly_72h, now, &config), StorageTier::Warm);
    }

    #[test]
    fn classify_tier_just_under_72h() {
        let config = TieredStorageConfig::default();
        let now = Utc::now();
        let just_under = now - Duration::hours(71);
        assert_eq!(classify_tier(just_under, now, &config), StorageTier::Hot);
    }

    #[test]
    fn classify_tier_boundary_at_90d() {
        let config = TieredStorageConfig::default();
        let now = Utc::now();
        // Exactly 90 days should be cold
        let exactly_90d = now - Duration::days(90);
        assert_eq!(classify_tier(exactly_90d, now, &config), StorageTier::Cold);
    }

    #[test]
    fn classify_tier_just_under_90d() {
        let config = TieredStorageConfig::default();
        let now = Utc::now();
        let just_under = now - Duration::days(89);
        assert_eq!(classify_tier(just_under, now, &config), StorageTier::Warm);
    }

    // ---- TieredStorageConfig tests ----

    #[test]
    fn tiered_storage_config_defaults() {
        let config = TieredStorageConfig::default();
        assert_eq!(config.hot_retention_hours, 72);
        assert_eq!(config.warm_retention_days, 90);
        assert_eq!(config.s3_bucket, "tameshi-ledger");
        assert_eq!(config.s3_prefix, "merkle-ledger/");
        assert!(config.object_lock_enabled);
    }

    #[test]
    fn tiered_storage_config_serde_roundtrip() {
        let config = TieredStorageConfig {
            hot_retention_hours: 48,
            warm_retention_days: 180,
            s3_bucket: "custom-bucket".to_string(),
            s3_prefix: "prefix/".to_string(),
            object_lock_enabled: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let restored: TieredStorageConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.hot_retention_hours, 48);
        assert_eq!(restored.warm_retention_days, 180);
        assert_eq!(restored.s3_bucket, "custom-bucket");
        assert_eq!(restored.s3_prefix, "prefix/");
        assert!(!restored.object_lock_enabled);
    }

    #[test]
    fn tiered_storage_config_custom_retention() {
        let config = TieredStorageConfig {
            hot_retention_hours: 24,
            warm_retention_days: 365,
            ..TieredStorageConfig::default()
        };
        assert_eq!(config.hot_retention_hours, 24);
        assert_eq!(config.warm_retention_days, 365);
        // Other fields remain default
        assert_eq!(config.s3_bucket, "tameshi-ledger");
    }

    // ---- StorageTier serde tests ----

    #[test]
    fn storage_tier_serde_hot() {
        let tier = StorageTier::Hot;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, "\"hot\"");
        let back: StorageTier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, StorageTier::Hot);
    }

    #[test]
    fn storage_tier_serde_warm() {
        let tier = StorageTier::Warm;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, "\"warm\"");
        let back: StorageTier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, StorageTier::Warm);
    }

    #[test]
    fn storage_tier_serde_cold() {
        let tier = StorageTier::Cold;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, "\"cold\"");
        let back: StorageTier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, StorageTier::Cold);
    }

    #[test]
    fn storage_tier_serde_all_variants() {
        for tier in &[StorageTier::Hot, StorageTier::Warm, StorageTier::Cold] {
            let json = serde_json::to_string(tier).unwrap();
            let back: StorageTier = serde_json::from_str(&json).unwrap();
            assert_eq!(*tier, back);
        }
    }

    // ---- StorageStats serde tests ----

    #[test]
    fn storage_stats_serde_roundtrip() {
        let now = Utc::now();
        let stats = StorageStats {
            hot_entries: 100,
            warm_entries: 500,
            cold_entries: 2000,
            total_entries: 2600,
            oldest_hot: Some(now - Duration::hours(70)),
            newest_hot: Some(now),
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: StorageStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hot_entries, 100);
        assert_eq!(back.warm_entries, 500);
        assert_eq!(back.cold_entries, 2000);
        assert_eq!(back.total_entries, 2600);
        assert!(back.oldest_hot.is_some());
        assert!(back.newest_hot.is_some());
    }

    #[test]
    fn storage_stats_serde_empty() {
        let stats = StorageStats {
            hot_entries: 0,
            warm_entries: 0,
            cold_entries: 0,
            total_entries: 0,
            oldest_hot: None,
            newest_hot: None,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: StorageStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hot_entries, 0);
        assert!(back.oldest_hot.is_none());
        assert!(back.newest_hot.is_none());
    }

    // ---- TieredLedgerStore tests ----

    #[test]
    fn tiered_store_new_is_empty() {
        let store = TieredLedgerStore::new(TieredStorageConfig::default());
        assert_eq!(store.hot_count(), 0);
        assert_eq!(store.warm_evicted_count(), 0);
    }

    #[test]
    fn tiered_store_config_accessor() {
        let config = TieredStorageConfig {
            hot_retention_hours: 24,
            ..TieredStorageConfig::default()
        };
        let store = TieredLedgerStore::new(config);
        assert_eq!(store.config().hot_retention_hours, 24);
    }

    #[tokio::test]
    async fn tiered_store_hot_count() {
        let store = TieredLedgerStore::new(TieredStorageConfig::default());
        let entry = make_entry_at(Utc::now());
        store.hot.append(entry).await.unwrap();
        assert_eq!(store.hot_count(), 1);
    }

    #[tokio::test]
    async fn tiered_store_hot_count_multiple() {
        let store = TieredLedgerStore::new(TieredStorageConfig::default());
        for i in 0..5 {
            let mut entry = make_entry_at(Utc::now());
            entry.sequence = i;
            store.hot.append(entry).await.unwrap();
        }
        assert_eq!(store.hot_count(), 5);
    }

    #[tokio::test]
    async fn evict_to_warm_moves_old_entries() {
        let store = TieredLedgerStore::new(TieredStorageConfig::default());
        let now = Utc::now();

        // Add an entry from 100 hours ago (should be evicted)
        let old_entry = make_entry_at(now - Duration::hours(100));
        store.hot.append(old_entry).await.unwrap();

        // Add a recent entry (should stay)
        let recent_entry = make_entry_at(now - Duration::hours(1));
        store.hot.append(recent_entry).await.unwrap();

        assert_eq!(store.hot_count(), 2);
        let evicted = store.evict_to_warm_at(now);
        assert_eq!(evicted, 1);
        assert_eq!(store.hot_count(), 1);
        assert_eq!(store.warm_evicted_count(), 1);
    }

    #[tokio::test]
    async fn evict_to_warm_no_old_entries() {
        let store = TieredLedgerStore::new(TieredStorageConfig::default());
        let now = Utc::now();

        let recent = make_entry_at(now - Duration::hours(1));
        store.hot.append(recent).await.unwrap();

        let evicted = store.evict_to_warm_at(now);
        assert_eq!(evicted, 0);
        assert_eq!(store.hot_count(), 1);
        assert_eq!(store.warm_evicted_count(), 0);
    }

    #[tokio::test]
    async fn evict_to_warm_all_old() {
        let store = TieredLedgerStore::new(TieredStorageConfig::default());
        let now = Utc::now();

        for _ in 0..3 {
            let old = make_entry_at(now - Duration::hours(200));
            store.hot.append(old).await.unwrap();
        }

        let evicted = store.evict_to_warm_at(now);
        assert_eq!(evicted, 3);
        assert_eq!(store.hot_count(), 0);
        assert_eq!(store.warm_evicted_count(), 3);
    }

    #[tokio::test]
    async fn evict_to_warm_accumulates() {
        let store = TieredLedgerStore::new(TieredStorageConfig::default());
        let now = Utc::now();

        let old = make_entry_at(now - Duration::hours(200));
        store.hot.append(old).await.unwrap();
        store.evict_to_warm_at(now);
        assert_eq!(store.warm_evicted_count(), 1);

        let old2 = make_entry_at(now - Duration::hours(300));
        store.hot.append(old2).await.unwrap();
        store.evict_to_warm_at(now);
        assert_eq!(store.warm_evicted_count(), 2);
    }

    // ---- Stats tests ----

    #[tokio::test]
    async fn stats_empty_store() {
        let store = TieredLedgerStore::new(TieredStorageConfig::default());
        let stats = store.stats_at(Utc::now());
        assert_eq!(stats.hot_entries, 0);
        assert_eq!(stats.warm_entries, 0);
        assert_eq!(stats.cold_entries, 0);
        assert_eq!(stats.total_entries, 0);
        assert!(stats.oldest_hot.is_none());
        assert!(stats.newest_hot.is_none());
    }

    #[tokio::test]
    async fn stats_with_hot_entries() {
        let store = TieredLedgerStore::new(TieredStorageConfig::default());
        let now = Utc::now();

        let entry1 = make_entry_at(now - Duration::hours(2));
        let entry2 = make_entry_at(now - Duration::hours(1));
        store.hot.append(entry1).await.unwrap();
        store.hot.append(entry2).await.unwrap();

        let stats = store.stats_at(now);
        assert_eq!(stats.hot_entries, 2);
        assert!(stats.oldest_hot.is_some());
        assert!(stats.newest_hot.is_some());
    }

    #[tokio::test]
    async fn stats_after_eviction() {
        let store = TieredLedgerStore::new(TieredStorageConfig::default());
        let now = Utc::now();

        let old = make_entry_at(now - Duration::hours(100));
        let recent = make_entry_at(now - Duration::hours(1));
        store.hot.append(old).await.unwrap();
        store.hot.append(recent).await.unwrap();

        store.evict_to_warm_at(now);

        let stats = store.stats_at(now);
        assert_eq!(stats.hot_entries, 1);
        assert_eq!(stats.warm_entries, 1);
        assert_eq!(stats.total_entries, 2);
    }

    // ---- Custom retention hours ----

    #[tokio::test]
    async fn custom_retention_hours() {
        let config = TieredStorageConfig {
            hot_retention_hours: 24,
            ..TieredStorageConfig::default()
        };
        let store = TieredLedgerStore::new(config);
        let now = Utc::now();

        // 30 hours old — should be evicted with 24h retention
        let entry = make_entry_at(now - Duration::hours(30));
        store.hot.append(entry).await.unwrap();

        let evicted = store.evict_to_warm_at(now);
        assert_eq!(evicted, 1);
    }

    #[tokio::test]
    async fn custom_retention_hours_keeps_within_window() {
        let config = TieredStorageConfig {
            hot_retention_hours: 168, // 7 days
            ..TieredStorageConfig::default()
        };
        let store = TieredLedgerStore::new(config);
        let now = Utc::now();

        // 100 hours old — still within 168h window
        let entry = make_entry_at(now - Duration::hours(100));
        store.hot.append(entry).await.unwrap();

        let evicted = store.evict_to_warm_at(now);
        assert_eq!(evicted, 0);
    }

    // ---- classify_tier with custom config ----

    #[test]
    fn classify_tier_custom_config() {
        let config = TieredStorageConfig {
            hot_retention_hours: 24,
            warm_retention_days: 30,
            ..TieredStorageConfig::default()
        };
        let now = Utc::now();

        assert_eq!(
            classify_tier(now - Duration::hours(12), now, &config),
            StorageTier::Hot
        );
        assert_eq!(
            classify_tier(now - Duration::days(10), now, &config),
            StorageTier::Warm
        );
        assert_eq!(
            classify_tier(now - Duration::days(60), now, &config),
            StorageTier::Cold
        );
    }

    #[test]
    fn classify_tier_zero_age() {
        let config = TieredStorageConfig::default();
        let now = Utc::now();
        assert_eq!(classify_tier(now, now, &config), StorageTier::Hot);
    }

    // ---- Default config values ----

    #[test]
    fn default_config_values_correct() {
        let config = TieredStorageConfig::default();
        assert_eq!(config.hot_retention_hours, 72);
        assert_eq!(config.warm_retention_days, 90);
        assert_eq!(config.s3_bucket, "tameshi-ledger");
        assert_eq!(config.s3_prefix, "merkle-ledger/");
        assert!(config.object_lock_enabled);
    }

    // ---- StorageTier equality ----

    #[test]
    fn storage_tier_equality() {
        assert_eq!(StorageTier::Hot, StorageTier::Hot);
        assert_eq!(StorageTier::Warm, StorageTier::Warm);
        assert_eq!(StorageTier::Cold, StorageTier::Cold);
        assert_ne!(StorageTier::Hot, StorageTier::Warm);
        assert_ne!(StorageTier::Warm, StorageTier::Cold);
        assert_ne!(StorageTier::Hot, StorageTier::Cold);
    }

    // ---- StorageTier clone ----

    #[test]
    fn storage_tier_clone() {
        let tier = StorageTier::Warm;
        let cloned = tier.clone();
        assert_eq!(tier, cloned);
    }

    // ---- TieredStorageConfig clone ----

    #[test]
    fn tiered_storage_config_clone() {
        let config = TieredStorageConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.hot_retention_hours, config.hot_retention_hours);
        assert_eq!(cloned.warm_retention_days, config.warm_retention_days);
        assert_eq!(cloned.s3_bucket, config.s3_bucket);
    }

    // ---- StorageStats clone ----

    #[test]
    fn storage_stats_clone() {
        let stats = StorageStats {
            hot_entries: 10,
            warm_entries: 20,
            cold_entries: 30,
            total_entries: 60,
            oldest_hot: Some(Utc::now()),
            newest_hot: Some(Utc::now()),
        };
        let cloned = stats.clone();
        assert_eq!(cloned.hot_entries, 10);
        assert_eq!(cloned.warm_entries, 20);
        assert_eq!(cloned.cold_entries, 30);
        assert_eq!(cloned.total_entries, 60);
    }
}
