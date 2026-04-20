//! Layered configuration system.
//!
//! Provides a unified configuration loading pattern:
//! **defaults → YAML file → environment variables**
//!
//! Each layer overrides the previous. Environment variables always win.
//!
//! # Usage
//!
//! ```rust,ignore
//! use serde::{Deserialize, Serialize};
//! use tameshi::config::load_config;
//!
//! #[derive(Clone, Debug, Serialize, Deserialize)]
//! struct MyConfig {
//!     listen_addr: String,
//!     log_level: String,
//! }
//!
//! impl Default for MyConfig {
//!     fn default() -> Self {
//!         Self {
//!             listen_addr: "0.0.0.0:8080".to_string(),
//!             log_level: "info".to_string(),
//!         }
//!     }
//! }
//!
//! // Loads from: defaults → ./config.yaml (if exists) → MYAPP_ env vars
//! let config: MyConfig = load_config("MYAPP", &["config.yaml", "/etc/myapp/config.yaml"])
//!     .expect("config loading failed");
//! ```
//!
//! # Environment Variable Mapping
//!
//! Struct fields are mapped to env vars using the prefix and SCREAMING_SNAKE_CASE:
//! - `listen_addr` → `MYAPP_LISTEN_ADDR`
//! - `log_level` → `MYAPP_LOG_LEVEL`
//!
//! Nested structs use double underscores:
//! - `tls.cert_path` → `MYAPP_TLS__CERT_PATH`

use serde::de::DeserializeOwned;
use serde::Serialize;

// Config loading delegates to shikumi's ProviderChain — the pleme-io
// standard. shikumi wraps figment behind a fluent API; the public
// trait surface here is unchanged.

use crate::error::TameshiError;

/// Abstraction over configuration loading.
///
/// Allows consumers to inject custom config loading strategies
/// (e.g., loading from Kubernetes ConfigMaps, remote endpoints, etc.)
/// while keeping the same interface.
pub trait ConfigLoader: Send + Sync {
    /// Load configuration from the provider.
    fn load<T>(&self) -> Result<T, TameshiError>
    where
        T: Default + Serialize + serde::de::DeserializeOwned;
}

/// Default config loader using the layered pattern (defaults → YAML → env).
///
/// Historically called `FigmentConfigLoader` — name retained for API
/// stability. Internals delegate to shikumi's `ProviderChain`.
pub struct FigmentConfigLoader {
    /// Environment variable prefix.
    pub env_prefix: String,
    /// YAML file paths to search.
    pub yaml_paths: Vec<String>,
}

impl FigmentConfigLoader {
    /// Create a new layered config loader.
    #[must_use]
    pub fn new(env_prefix: &str, yaml_paths: &[&str]) -> Self {
        Self {
            env_prefix: env_prefix.to_string(),
            yaml_paths: yaml_paths.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl ConfigLoader for FigmentConfigLoader {
    fn load<T>(&self) -> Result<T, TameshiError>
    where
        T: Default + Serialize + serde::de::DeserializeOwned,
    {
        let path_refs: Vec<&str> = self.yaml_paths.iter().map(|s| s.as_str()).collect();
        load_config(&self.env_prefix, &path_refs)
    }
}

/// Load a configuration using the layered pattern: defaults → YAML → env vars.
///
/// - `env_prefix`: Environment variable prefix (e.g., `"SEKIBAN"` → `SEKIBAN_LISTEN_ADDR`)
/// - `yaml_paths`: List of YAML file paths to try, in order. First existing file wins.
///
/// Returns the fully merged configuration or an error.
pub fn load_config<T>(env_prefix: &str, yaml_paths: &[&str]) -> Result<T, TameshiError>
where
    T: Default + Serialize + DeserializeOwned,
{
    let mut chain = shikumi::ProviderChain::new().with_defaults(&T::default());

    // Merge the first YAML file that exists.
    for path in yaml_paths {
        let p = std::path::Path::new(path);
        if p.exists() {
            chain = chain.with_file(p);
            break;
        }
    }

    // Environment variables override everything.
    chain = chain.with_env(&format!("{}_", env_prefix));

    chain.extract().map_err(|e| {
        TameshiError::ConfigError(format!("failed to load config: {e}"))
    })
}

/// Load config with an explicit YAML path (no search).
///
/// Useful when the YAML path is itself configured via env var or CLI arg.
pub fn load_config_from<T>(env_prefix: &str, yaml_path: Option<&str>) -> Result<T, TameshiError>
where
    T: Default + Serialize + DeserializeOwned,
{
    let paths: Vec<&str> = yaml_path.into_iter().collect();
    load_config(env_prefix, &paths)
}

/// Load config with defaults only and env var overrides (no YAML).
///
/// Minimal mode for CLI tools or containers where YAML isn't needed.
pub fn load_config_env_only<T>(env_prefix: &str) -> Result<T, TameshiError>
where
    T: Default + Serialize + DeserializeOwned,
{
    load_config::<T>(env_prefix, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
    struct TestConfig {
        host: String,
        port: u16,
        debug: bool,
    }

    // Note: We can't implement Default twice, so we test via Serialized defaults directly

    #[test]
    fn load_with_defaults_only() {
        // No YAML files exist, no env vars set → should get defaults
        let config: TestConfig =
            load_config("TAMESHI_TEST_CFG", &["/nonexistent/path.yaml"]).unwrap();
        assert_eq!(config.host, "");
        assert_eq!(config.port, 0);
        assert!(!config.debug);
    }

    #[test]
    fn load_from_yaml_file() {
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("test-config.yaml");
        std::fs::write(
            &yaml_path,
            "host: 0.0.0.0\nport: 9090\ndebug: true\n",
        )
        .unwrap();

        let config: TestConfig =
            load_config("TAMESHI_TEST_YAML", &[yaml_path.to_str().unwrap()]).unwrap();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 9090);
        assert!(config.debug);
    }

    #[test]
    fn env_overrides_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("override-config.yaml");
        std::fs::write(
            &yaml_path,
            "host: from-yaml\nport: 3000\ndebug: false\n",
        )
        .unwrap();

        // Set env var to override host
        // SAFETY: test-only, single-threaded access to env vars
        unsafe { std::env::set_var("TAMESHI_TEST_OVR_HOST", "from-env") };

        let config: TestConfig =
            load_config("TAMESHI_TEST_OVR", &[yaml_path.to_str().unwrap()]).unwrap();

        assert_eq!(config.host, "from-env");
        assert_eq!(config.port, 3000); // from yaml
        assert!(!config.debug); // from yaml

        // Clean up
        // SAFETY: test-only, single-threaded access to env vars
        unsafe { std::env::remove_var("TAMESHI_TEST_OVR_HOST") };
    }

    #[test]
    fn env_only_mode() {
        // SAFETY: test-only, single-threaded access to env vars
        unsafe { std::env::set_var("TAMESHI_TEST_ENV_PORT", "4000") };

        let config: TestConfig = load_config_env_only("TAMESHI_TEST_ENV").unwrap();
        assert_eq!(config.port, 4000);

        // SAFETY: test-only, single-threaded access to env vars
        unsafe { std::env::remove_var("TAMESHI_TEST_ENV_PORT") };
    }

    #[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
    struct NestedConfig {
        server: ServerConfig,
        log_level: String,
    }

    #[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
    struct ServerConfig {
        host: String,
        port: u16,
    }

    #[test]
    fn nested_config_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("nested-config.yaml");
        std::fs::write(
            &yaml_path,
            "server:\n  host: 10.0.0.1\n  port: 5000\nlog_level: debug\n",
        )
        .unwrap();

        let config: NestedConfig =
            load_config("TAMESHI_TEST_NESTED", &[yaml_path.to_str().unwrap()]).unwrap();
        assert_eq!(config.server.host, "10.0.0.1");
        assert_eq!(config.server.port, 5000);
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn nested_env_override_with_double_underscore() {
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("nested-env-config.yaml");
        std::fs::write(
            &yaml_path,
            "server:\n  host: from-yaml\n  port: 5000\nlog_level: info\n",
        )
        .unwrap();

        // SAFETY: test-only, single-threaded access to env vars
        unsafe {
            std::env::set_var("TAMESHI_TEST_NENV_SERVER__HOST", "from-env");
            std::env::set_var("TAMESHI_TEST_NENV_LOG_LEVEL", "trace");
        }

        let config: NestedConfig =
            load_config("TAMESHI_TEST_NENV", &[yaml_path.to_str().unwrap()]).unwrap();

        assert_eq!(config.server.host, "from-env");
        assert_eq!(config.server.port, 5000); // from yaml
        assert_eq!(config.log_level, "trace"); // from env

        // SAFETY: test-only, single-threaded access to env vars
        unsafe {
            std::env::remove_var("TAMESHI_TEST_NENV_SERVER__HOST");
            std::env::remove_var("TAMESHI_TEST_NENV_LOG_LEVEL");
        }
    }

    #[test]
    fn figment_config_loader_loads_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("figment-test.yaml");
        std::fs::write(
            &yaml_path,
            "host: figment-host\nport: 7777\ndebug: true\n",
        )
        .unwrap();

        let loader = FigmentConfigLoader::new(
            "TAMESHI_FIG_TEST",
            &[yaml_path.to_str().unwrap()],
        );
        let config: TestConfig = loader.load().unwrap();
        assert_eq!(config.host, "figment-host");
        assert_eq!(config.port, 7777);
        assert!(config.debug);
    }

    #[test]
    fn missing_config_file_returns_defaults() {
        let config: TestConfig =
            load_config("TAMESHI_MISSING_CFG", &[
                "/absolutely/nonexistent/path1.yaml",
                "/absolutely/nonexistent/path2.yaml",
            ]).unwrap();
        // Should get the Default values (all zero/empty for TestConfig)
        assert_eq!(config.host, "");
        assert_eq!(config.port, 0);
        assert!(!config.debug);
    }

    #[test]
    fn load_config_from_explicit_path() {
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("explicit.yaml");
        std::fs::write(&yaml_path, "host: explicit\nport: 6000\n").unwrap();

        let config: TestConfig =
            load_config_from("TAMESHI_EXPLICIT", Some(yaml_path.to_str().unwrap())).unwrap();
        assert_eq!(config.host, "explicit");
        assert_eq!(config.port, 6000);
    }

    #[test]
    fn load_config_from_none_returns_defaults() {
        let config: TestConfig = load_config_from("TAMESHI_NONE_PATH", None).unwrap();
        assert_eq!(config.host, "");
        assert_eq!(config.port, 0);
    }

    #[test]
    fn first_existing_yaml_wins() {
        let dir = tempfile::tempdir().unwrap();
        let yaml1 = dir.path().join("first.yaml");
        let yaml2 = dir.path().join("second.yaml");
        std::fs::write(&yaml1, "host: first\nport: 1111\n").unwrap();
        std::fs::write(&yaml2, "host: second\nport: 2222\n").unwrap();

        let config: TestConfig = load_config(
            "TAMESHI_TEST_FIRST",
            &[yaml1.to_str().unwrap(), yaml2.to_str().unwrap()],
        )
        .unwrap();
        assert_eq!(config.host, "first");
        assert_eq!(config.port, 1111);
    }
}
