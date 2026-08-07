//! Plugin registry for compliance domain plugins.
//!
//! The [`PluginRegistry`] collects all registered [`CompliancePlugin`] implementations
//! and provides lookup by domain name and filtering by availability.

use std::sync::Arc;

use super::plugin::CompliancePlugin;

/// Registry of compliance domain plugins.
///
/// Built via [`PluginRegistryBuilder`], then shared via `Arc<PluginRegistry>`.
pub struct PluginRegistry {
    plugins: Vec<Arc<dyn CompliancePlugin>>,
}

/// Builder for constructing a [`PluginRegistry`].
pub struct PluginRegistryBuilder {
    plugins: Vec<Arc<dyn CompliancePlugin>>,
}

impl PluginRegistryBuilder {
    /// Create a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Register a compliance plugin.
    #[must_use]
    pub fn register(mut self, plugin: Arc<dyn CompliancePlugin>) -> Self {
        self.plugins.push(plugin);
        self
    }

    /// Build the registry.
    #[must_use]
    pub fn build(self) -> PluginRegistry {
        PluginRegistry {
            plugins: self.plugins,
        }
    }
}

impl Default for PluginRegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    /// All registered plugins.
    #[must_use]
    pub fn plugins(&self) -> &[Arc<dyn CompliancePlugin>] {
        &self.plugins
    }

    /// Find a plugin by domain name.
    #[must_use]
    pub fn get(&self, domain: &str) -> Option<&Arc<dyn CompliancePlugin>> {
        self.plugins.iter().find(|p| p.domain() == domain)
    }

    /// Return only available plugins.
    #[must_use]
    pub fn available(&self) -> Vec<&Arc<dyn CompliancePlugin>> {
        self.plugins.iter().filter(|p| p.is_available()).collect()
    }

    /// List all registered domain names.
    #[must_use]
    pub fn domains(&self) -> Vec<&str> {
        self.plugins.iter().map(|p| p.domain()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::plugin::MockPlugin;

    #[test]
    fn builder_creates_empty_registry() {
        let registry = PluginRegistryBuilder::new().build();
        assert!(registry.plugins().is_empty());
        assert!(registry.domains().is_empty());
    }

    #[test]
    fn builder_registers_single_plugin() {
        let plugin = Arc::new(MockPlugin::new("test"));
        let registry = PluginRegistryBuilder::new().register(plugin).build();
        assert_eq!(registry.plugins().len(), 1);
        assert_eq!(registry.domains(), vec!["test"]);
    }

    #[test]
    fn builder_registers_multiple_plugins() {
        let registry = PluginRegistryBuilder::new()
            .register(Arc::new(MockPlugin::new("alpha")))
            .register(Arc::new(MockPlugin::new("beta")))
            .register(Arc::new(MockPlugin::new("gamma")))
            .build();
        assert_eq!(registry.plugins().len(), 3);
        assert_eq!(registry.domains(), vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn get_finds_plugin_by_domain() {
        let registry = PluginRegistryBuilder::new()
            .register(Arc::new(MockPlugin::new("kernel")))
            .register(Arc::new(MockPlugin::new("nix-store")))
            .build();

        let found = registry.get("kernel");
        assert!(found.is_some());
        assert_eq!(found.unwrap().domain(), "kernel");
    }

    #[test]
    fn get_returns_none_for_unknown_domain() {
        let registry = PluginRegistryBuilder::new()
            .register(Arc::new(MockPlugin::new("kernel")))
            .build();
        assert!(registry.get("unknown").is_none());
    }

    #[test]
    fn available_filters_unavailable_plugins() {
        let registry = PluginRegistryBuilder::new()
            .register(Arc::new(MockPlugin::new("available").with_available(true)))
            .register(Arc::new(
                MockPlugin::new("unavailable").with_available(false),
            ))
            .register(Arc::new(
                MockPlugin::new("also-available").with_available(true),
            ))
            .build();

        let avail = registry.available();
        assert_eq!(avail.len(), 2);
        let domains: Vec<&str> = avail.iter().map(|p| p.domain()).collect();
        assert!(domains.contains(&"available"));
        assert!(domains.contains(&"also-available"));
        assert!(!domains.contains(&"unavailable"));
    }

    #[test]
    fn available_returns_empty_when_none_available() {
        let registry = PluginRegistryBuilder::new()
            .register(Arc::new(MockPlugin::new("a").with_available(false)))
            .register(Arc::new(MockPlugin::new("b").with_available(false)))
            .build();
        assert!(registry.available().is_empty());
    }

    #[test]
    fn available_returns_all_when_all_available() {
        let registry = PluginRegistryBuilder::new()
            .register(Arc::new(MockPlugin::new("a").with_available(true)))
            .register(Arc::new(MockPlugin::new("b").with_available(true)))
            .build();
        assert_eq!(registry.available().len(), 2);
    }

    #[test]
    fn empty_registry_get_returns_none() {
        let registry = PluginRegistryBuilder::new().build();
        assert!(registry.get("anything").is_none());
    }

    #[test]
    fn empty_registry_available_returns_empty() {
        let registry = PluginRegistryBuilder::new().build();
        assert!(registry.available().is_empty());
    }

    #[test]
    fn builder_default_is_empty() {
        let builder = PluginRegistryBuilder::default();
        let registry = builder.build();
        assert!(registry.plugins().is_empty());
    }

    #[test]
    fn domains_preserves_insertion_order() {
        let registry = PluginRegistryBuilder::new()
            .register(Arc::new(MockPlugin::new("zulu")))
            .register(Arc::new(MockPlugin::new("alpha")))
            .register(Arc::new(MockPlugin::new("mike")))
            .build();
        assert_eq!(registry.domains(), vec!["zulu", "alpha", "mike"]);
    }

    #[test]
    fn get_returns_first_match_on_duplicate_domains() {
        let registry = PluginRegistryBuilder::new()
            .register(Arc::new(MockPlugin::new("dup").with_pass_all(true)))
            .register(Arc::new(MockPlugin::new("dup").with_pass_all(false)))
            .build();
        // get returns the first registered
        let found = registry.get("dup").unwrap();
        assert_eq!(found.domain(), "dup");
    }
}
