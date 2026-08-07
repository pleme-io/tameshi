//! Generic trait-parameterized collectors.
//!
//! These collectors accept `CommandRunner`, `FileSystem`, and `HttpClient`
//! trait bounds instead of calling real infrastructure directly. This makes
//! them fully testable with mocks.
//!
//! The concrete collectors in sibling modules (`nix`, `oci`, `helm`, etc.)
//! remain unchanged and use real I/O. These generic versions provide an
//! alternative path for consumers who want maximum testability.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};
use crate::traits::{CommandRunner, FileSystem, HttpClient};

use super::traits::LayerCollector;

use tracing::debug;

// ---------------------------------------------------------------------------
// Generic Nix Collector
// ---------------------------------------------------------------------------

/// Nix store closure collector parameterized over a [`CommandRunner`].
///
/// This collector can be tested without real `nix-store` by injecting a
/// [`MockCommandRunner`](crate::traits::MockCommandRunner).
pub struct GenericNixCollector<C: CommandRunner = crate::traits::SystemCommandRunner> {
    /// Optional Nix store path. If `None`, the system profile is hashed.
    pub store_path: Option<String>,
    /// Command runner for subprocess execution.
    pub cmd: C,
}

impl<C: CommandRunner> GenericNixCollector<C> {
    /// Create a collector for a specific store path.
    pub fn new(store_path: Option<String>, cmd: C) -> Self {
        Self { store_path, cmd }
    }

    /// Hash a Nix store closure via the injected command runner.
    async fn hash_closure(&self, store_path: &str) -> Result<LayerSignature> {
        let output = self
            .cmd
            .run("nix-store", &["--query", "--requisites", store_path])
            .await?;

        let mut paths: Vec<&str> = output.lines().filter(|l| !l.is_empty()).collect();
        paths.sort();

        debug!(path_count = paths.len(), "Hashing Nix closure (generic)");

        let mut inputs = Vec::with_capacity(paths.len());
        for path in &paths {
            let hash = match self.cmd.run_raw("nix-store", &["--dump", path]).await {
                Ok(data) => Blake3Hash::digest(&data),
                Err(_) => {
                    debug!(path = path, "nix-store --dump failed, hashing path string");
                    Blake3Hash::digest(path.as_bytes())
                }
            };
            inputs.push(InputHash {
                name: path.to_string(),
                hash,
                size_bytes: None,
            });
        }

        let composite = compute_composite_hash(&inputs);
        Ok(LayerSignature::new(
            LayerType::Nix,
            composite,
            store_path,
            inputs,
        ))
    }
}

impl<C: CommandRunner> LayerCollector for GenericNixCollector<C> {
    async fn collect(&self) -> Result<LayerSignature> {
        match &self.store_path {
            Some(path) => self.hash_closure(path).await,
            None => {
                // For system profile, we'd need FileSystem trait too;
                // for now, just error in the generic version.
                Err(TameshiError::CollectorError {
                    layer: "nix".to_string(),
                    message: "GenericNixCollector requires an explicit store_path".to_string(),
                })
            }
        }
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Nix
    }
}

// ---------------------------------------------------------------------------
// Generic OCI Collector
// ---------------------------------------------------------------------------

/// OCI image manifest collector parameterized over a [`CommandRunner`].
pub struct GenericOciCollector<C: CommandRunner = crate::traits::SystemCommandRunner> {
    /// OCI image reference.
    pub image_ref: String,
    /// Command runner for subprocess execution.
    pub cmd: C,
}

impl<C: CommandRunner> GenericOciCollector<C> {
    /// Create a collector for a specific image reference.
    pub fn new(image_ref: &str, cmd: C) -> Self {
        Self {
            image_ref: image_ref.to_string(),
            cmd,
        }
    }
}

impl<C: CommandRunner> LayerCollector for GenericOciCollector<C> {
    async fn collect(&self) -> Result<LayerSignature> {
        let docker_ref = if self.image_ref.starts_with("docker://") {
            self.image_ref.clone()
        } else {
            format!("docker://{}", self.image_ref)
        };

        let manifest_bytes = self
            .cmd
            .run_raw("skopeo", &["inspect", "--raw", &docker_ref])
            .await?;

        let manifest_hash = Blake3Hash::digest(&manifest_bytes);
        let inputs = super::oci::parse_manifest_layers(&manifest_bytes, &self.image_ref)?;

        debug!(
            image = self.image_ref.as_str(),
            layers = inputs.len(),
            "Hashed OCI manifest (generic)"
        );

        Ok(LayerSignature::new(
            LayerType::Oci,
            manifest_hash,
            &self.image_ref,
            inputs,
        ))
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Oci
    }
}

// ---------------------------------------------------------------------------
// Generic Kubernetes Collector
// ---------------------------------------------------------------------------

/// Kubernetes namespace state collector parameterized over a [`CommandRunner`].
pub struct GenericKubernetesCollector<C: CommandRunner = crate::traits::SystemCommandRunner> {
    /// Namespace to hash.
    pub namespace: String,
    /// Command runner for subprocess execution.
    pub cmd: C,
}

impl<C: CommandRunner> GenericKubernetesCollector<C> {
    /// Create a collector for a namespace.
    pub fn new(namespace: &str, cmd: C) -> Self {
        Self {
            namespace: namespace.to_string(),
            cmd,
        }
    }
}

impl<C: CommandRunner> LayerCollector for GenericKubernetesCollector<C> {
    async fn collect(&self) -> Result<LayerSignature> {
        let resource_types = [
            "deployments",
            "statefulsets",
            "daemonsets",
            "services",
            "configmaps",
            "secrets",
            "ingresses",
            "networkpolicies",
        ];

        let mut inputs = Vec::new();

        for resource_type in &resource_types {
            match self
                .cmd
                .run(
                    "kubectl",
                    &["get", resource_type, "-n", &self.namespace, "-o", "json"],
                )
                .await
            {
                Ok(output) => {
                    if let Ok(mut resources) = serde_json::from_str::<serde_json::Value>(&output) {
                        super::kubernetes::strip_volatile_fields(&mut resources);
                        let canonical = serde_json::to_vec(&resources)?;
                        inputs.push(InputHash {
                            name: format!("{}/{}", self.namespace, resource_type),
                            hash: Blake3Hash::digest(&canonical),
                            size_bytes: Some(canonical.len() as u64),
                        });
                    }
                }
                Err(_) => {
                    // Resource type may not exist in this cluster
                }
            }
        }

        let composite = compute_composite_hash(&inputs);

        debug!(
            namespace = self.namespace.as_str(),
            resource_types = inputs.len(),
            "Hashed Kubernetes namespace state (generic)"
        );

        Ok(LayerSignature::new(
            LayerType::Kubernetes,
            composite,
            &format!("namespace:{}", self.namespace),
            inputs,
        ))
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Kubernetes
    }
}

// ---------------------------------------------------------------------------
// Generic Tatara Collector (HTTP-based)
// ---------------------------------------------------------------------------

/// Tatara cluster state collector parameterized over an [`HttpClient`].
pub struct GenericTataraApiCollector<H: HttpClient = crate::traits::ReqwestHttpClient> {
    /// Tatara API URL.
    pub api_url: String,
    /// HTTP client.
    pub client: H,
}

impl<H: HttpClient> GenericTataraApiCollector<H> {
    /// Create a collector for the Tatara API.
    pub fn new(api_url: &str, client: H) -> Self {
        Self {
            api_url: api_url.to_string(),
            client,
        }
    }
}

impl<H: HttpClient> LayerCollector for GenericTataraApiCollector<H> {
    async fn collect(&self) -> Result<LayerSignature> {
        let url = format!("{}/api/v1/state", self.api_url);
        let state: serde_json::Value = self.client.get_json(&url).await?;

        let canonical = serde_json::to_vec(&state)?;
        let hash = Blake3Hash::digest(&canonical);

        let inputs = vec![InputHash {
            name: "cluster-state-api".to_string(),
            hash: hash.clone(),
            size_bytes: Some(canonical.len() as u64),
        }];

        Ok(LayerSignature::new(
            LayerType::Tatara,
            hash,
            &self.api_url,
            inputs,
        ))
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Tatara
    }
}

// ---------------------------------------------------------------------------
// Generic Tofu Collector (command-based)
// ---------------------------------------------------------------------------

/// OpenTofu plan collector parameterized over a [`CommandRunner`].
pub struct GenericTofuCollector<C: CommandRunner = crate::traits::SystemCommandRunner> {
    /// Source for collection.
    pub source: GenericTofuSource,
    /// Command runner.
    pub cmd: C,
}

/// Source for generic tofu collection.
pub enum GenericTofuSource {
    /// Hash a plan file via `tofu show -json`.
    PlanFile(String),
    /// Hash remote state via `tofu state pull`.
    RemoteState(String),
}

impl<C: CommandRunner> GenericTofuCollector<C> {
    /// Create a collector for a plan file.
    pub fn from_plan(plan_path: &str, cmd: C) -> Self {
        Self {
            source: GenericTofuSource::PlanFile(plan_path.to_string()),
            cmd,
        }
    }

    /// Create a collector for remote state.
    pub fn from_remote(working_dir: &str, cmd: C) -> Self {
        Self {
            source: GenericTofuSource::RemoteState(working_dir.to_string()),
            cmd,
        }
    }
}

impl<C: CommandRunner> LayerCollector for GenericTofuCollector<C> {
    async fn collect(&self) -> Result<LayerSignature> {
        match &self.source {
            GenericTofuSource::PlanFile(path) => {
                let output = self.cmd.run("tofu", &["show", "-json", path]).await?;
                let plan_hash = Blake3Hash::digest(output.as_bytes());
                let inputs = vec![InputHash {
                    name: "plan".to_string(),
                    hash: plan_hash.clone(),
                    size_bytes: Some(output.len() as u64),
                }];
                Ok(LayerSignature::new(
                    LayerType::Tofu,
                    plan_hash,
                    path,
                    inputs,
                ))
            }
            GenericTofuSource::RemoteState(dir) => {
                let output = self.cmd.run_in_dir("tofu", &["state", "pull"], dir).await?;
                let state: serde_json::Value =
                    serde_json::from_str(&output).map_err(|e| TameshiError::CollectorError {
                        layer: "tofu".to_string(),
                        message: format!("failed to parse state: {e}"),
                    })?;
                let canonical = serde_json::to_vec(&state)?;
                let state_hash = Blake3Hash::digest(&canonical);
                let inputs = vec![InputHash {
                    name: "state".to_string(),
                    hash: state_hash.clone(),
                    size_bytes: Some(canonical.len() as u64),
                }];
                Ok(LayerSignature::new(
                    LayerType::Tofu,
                    state_hash,
                    dir,
                    inputs,
                ))
            }
        }
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Tofu
    }
}

// ---------------------------------------------------------------------------
// Generic Helm Collector (filesystem-based)
// ---------------------------------------------------------------------------

/// Helm chart collector parameterized over a [`FileSystem`].
pub struct GenericHelmCollector<F: FileSystem = crate::traits::RealFileSystem> {
    /// Chart directory path.
    pub chart_path: String,
    /// Filesystem implementation.
    pub fs: F,
}

impl<F: FileSystem> GenericHelmCollector<F> {
    /// Create a collector for a local chart directory.
    pub fn new(chart_path: &str, fs: F) -> Self {
        Self {
            chart_path: chart_path.to_string(),
            fs,
        }
    }
}

impl<F: FileSystem> LayerCollector for GenericHelmCollector<F> {
    async fn collect(&self) -> Result<LayerSignature> {
        let mut inputs = Vec::new();

        // Hash Chart.yaml
        let chart_yaml = format!("{}/Chart.yaml", self.chart_path);
        if let Ok(data) = self.fs.read_file(std::path::Path::new(&chart_yaml)).await {
            inputs.push(InputHash {
                name: "Chart.yaml".to_string(),
                hash: Blake3Hash::digest(&data),
                size_bytes: Some(data.len() as u64),
            });
        }

        // Hash values.yaml
        let values_yaml = format!("{}/values.yaml", self.chart_path);
        if let Ok(data) = self.fs.read_file(std::path::Path::new(&values_yaml)).await {
            inputs.push(InputHash {
                name: "values.yaml".to_string(),
                hash: Blake3Hash::digest(&data),
                size_bytes: Some(data.len() as u64),
            });
        }

        // Hash all templates
        let templates_dir = format!("{}/templates", self.chart_path);
        if let Ok(entries) = self.fs.read_dir(std::path::Path::new(&templates_dir)).await {
            let mut template_files = Vec::new();
            for entry_path in &entries {
                if let Ok(data) = self.fs.read_file(entry_path).await {
                    let name = entry_path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    template_files.push((name, data));
                }
            }
            template_files.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, data) in &template_files {
                inputs.push(InputHash {
                    name: format!("templates/{name}"),
                    hash: Blake3Hash::digest(data),
                    size_bytes: Some(data.len() as u64),
                });
            }
        }

        let composite = compute_composite_hash(&inputs);

        debug!(
            chart = self.chart_path.as_str(),
            files = inputs.len(),
            "Hashed Helm chart directory (generic)"
        );

        Ok(LayerSignature::new(
            LayerType::Helm,
            composite,
            &self.chart_path,
            inputs,
        ))
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Helm
    }
}

// ---------------------------------------------------------------------------
// Generic FluxCD Collector
// ---------------------------------------------------------------------------

/// FluxCD reconciliation state collector parameterized over a [`CommandRunner`].
///
/// This collector can be tested without real `kubectl` by injecting a
/// [`MockCommandRunner`](crate::traits::MockCommandRunner).
pub struct GenericFluxCDCollector<C: CommandRunner = crate::traits::SystemCommandRunner> {
    /// Namespace to query for FluxCD resources.
    pub namespace: String,
    /// Command runner for subprocess execution.
    pub cmd: C,
}

impl<C: CommandRunner> GenericFluxCDCollector<C> {
    /// Create a collector for a namespace.
    pub fn new(namespace: &str, cmd: C) -> Self {
        Self {
            namespace: namespace.to_string(),
            cmd,
        }
    }
}

impl<C: CommandRunner> LayerCollector for GenericFluxCDCollector<C> {
    async fn collect(&self) -> Result<LayerSignature> {
        let resource_types = [
            "kustomizations.kustomize.toolkit.fluxcd.io",
            "helmreleases.helm.toolkit.fluxcd.io",
            "gitrepositories.source.toolkit.fluxcd.io",
        ];

        let mut inputs = Vec::new();

        for resource_type in &resource_types {
            match self
                .cmd
                .run(
                    "kubectl",
                    &["get", resource_type, "-n", &self.namespace, "-o", "json"],
                )
                .await
            {
                Ok(output) => {
                    if let Ok(mut resources) = serde_json::from_str::<serde_json::Value>(&output) {
                        super::fluxcd::strip_fluxcd_volatile_fields(&mut resources);
                        let canonical = serde_json::to_vec(&resources)?;
                        inputs.push(InputHash {
                            name: format!("{}/{}", self.namespace, resource_type),
                            hash: Blake3Hash::digest(&canonical),
                            size_bytes: Some(canonical.len() as u64),
                        });
                    }
                }
                Err(_) => {
                    // Resource type may not exist in this cluster
                }
            }
        }

        let composite = compute_composite_hash(&inputs);

        debug!(
            namespace = self.namespace.as_str(),
            resource_types = inputs.len(),
            "Hashed FluxCD reconciliation state (generic)"
        );

        Ok(LayerSignature::new(
            LayerType::FluxCD,
            composite,
            &format!("fluxcd:{}", self.namespace),
            inputs,
        ))
    }

    fn layer_type(&self) -> LayerType {
        LayerType::FluxCD
    }
}

// ---------------------------------------------------------------------------
// Generic ArgoCD Collector
// ---------------------------------------------------------------------------

/// ArgoCD application state collector parameterized over a [`CommandRunner`].
///
/// This collector can be tested without real `kubectl` by injecting a
/// [`MockCommandRunner`](crate::traits::MockCommandRunner).
pub struct GenericArgoCDCollector<C: CommandRunner = crate::traits::SystemCommandRunner> {
    /// Namespace to query for ArgoCD resources.
    pub namespace: String,
    /// Command runner for subprocess execution.
    pub cmd: C,
}

impl<C: CommandRunner> GenericArgoCDCollector<C> {
    /// Create a collector for a namespace.
    pub fn new(namespace: &str, cmd: C) -> Self {
        Self {
            namespace: namespace.to_string(),
            cmd,
        }
    }
}

impl<C: CommandRunner> LayerCollector for GenericArgoCDCollector<C> {
    async fn collect(&self) -> Result<LayerSignature> {
        let resource_types = ["applications.argoproj.io", "applicationsets.argoproj.io"];

        let mut inputs = Vec::new();

        for resource_type in &resource_types {
            match self
                .cmd
                .run(
                    "kubectl",
                    &["get", resource_type, "-n", &self.namespace, "-o", "json"],
                )
                .await
            {
                Ok(output) => {
                    if let Ok(mut resources) = serde_json::from_str::<serde_json::Value>(&output) {
                        super::argocd::strip_argocd_volatile_fields(&mut resources);
                        let canonical = serde_json::to_vec(&resources)?;
                        inputs.push(InputHash {
                            name: format!("{}/{}", self.namespace, resource_type),
                            hash: Blake3Hash::digest(&canonical),
                            size_bytes: Some(canonical.len() as u64),
                        });
                    }
                }
                Err(_) => {
                    // Resource type may not exist in this cluster
                }
            }
        }

        let composite = compute_composite_hash(&inputs);

        debug!(
            namespace = self.namespace.as_str(),
            resource_types = inputs.len(),
            "Hashed ArgoCD application state (generic)"
        );

        Ok(LayerSignature::new(
            LayerType::ArgoCD,
            composite,
            &format!("argocd:{}", self.namespace),
            inputs,
        ))
    }

    fn layer_type(&self) -> LayerType {
        LayerType::ArgoCD
    }
}

// ---------------------------------------------------------------------------
// Generic Kindling Collector
// ---------------------------------------------------------------------------

/// Kindling identity/report collector parameterized over a [`CommandRunner`]
/// and [`FileSystem`].
///
/// This collector can be tested without real `kubectl` or filesystem access
/// by injecting [`MockCommandRunner`](crate::traits::MockCommandRunner) and
/// [`MockFileSystem`](crate::traits::MockFileSystem).
pub struct GenericKindlingCollector<
    C: CommandRunner = crate::traits::SystemCommandRunner,
    F: FileSystem = crate::traits::RealFileSystem,
> {
    /// Source to collect from.
    pub source: GenericKindlingSource,
    /// Command runner for subprocess execution.
    pub cmd: C,
    /// Filesystem implementation.
    pub fs: F,
}

/// Source for generic Kindling collection.
pub enum GenericKindlingSource {
    /// Hash a local identity document file.
    IdentityFile(String),
    /// Hash a compliance report file.
    ReportFile(String),
    /// Hash identity from a Kubernetes secret.
    K8sSecret {
        /// Kubernetes namespace.
        namespace: String,
        /// Secret name.
        secret_name: String,
    },
}

impl<C: CommandRunner, F: FileSystem> GenericKindlingCollector<C, F> {
    /// Create a collector for a local identity document.
    pub fn from_identity(identity_path: &str, cmd: C, fs: F) -> Self {
        Self {
            source: GenericKindlingSource::IdentityFile(identity_path.to_string()),
            cmd,
            fs,
        }
    }

    /// Create a collector for a compliance report.
    pub fn from_report(report_path: &str, cmd: C, fs: F) -> Self {
        Self {
            source: GenericKindlingSource::ReportFile(report_path.to_string()),
            cmd,
            fs,
        }
    }

    /// Create a collector for a Kubernetes secret.
    pub fn from_k8s_secret(namespace: &str, secret_name: &str, cmd: C, fs: F) -> Self {
        Self {
            source: GenericKindlingSource::K8sSecret {
                namespace: namespace.to_string(),
                secret_name: secret_name.to_string(),
            },
            cmd,
            fs,
        }
    }

    /// Hash a local identity document via the injected filesystem.
    async fn hash_identity_file(&self, path: &str) -> Result<LayerSignature> {
        let data = self
            .fs
            .read_file(std::path::Path::new(path))
            .await
            .map_err(|e| TameshiError::CollectorError {
                layer: "kindling".to_string(),
                message: format!("failed to read identity document {path}: {e}"),
            })?;

        // Parse and re-serialize for canonical form
        let identity: serde_json::Value =
            serde_json::from_slice(&data).map_err(|e| TameshiError::CollectorError {
                layer: "kindling".to_string(),
                message: format!("failed to parse identity document: {e}"),
            })?;

        let canonical = serde_json::to_vec(&identity)?;
        let hash = Blake3Hash::digest(&canonical);

        let mut inputs = vec![InputHash {
            name: "identity-document".to_string(),
            hash: hash.clone(),
            size_bytes: Some(canonical.len() as u64),
        }];

        // Extract certificate hashes if present
        if let Some(certs) = identity.get("certificates").and_then(|c| c.as_array()) {
            for (i, cert) in certs.iter().enumerate() {
                let cert_json = serde_json::to_vec(cert)?;
                inputs.push(InputHash {
                    name: format!("certificate-{i}"),
                    hash: Blake3Hash::digest(&cert_json),
                    size_bytes: Some(cert_json.len() as u64),
                });
            }
        }

        debug!(
            path = path,
            inputs = inputs.len(),
            "Hashed Kindling identity (generic)"
        );

        Ok(LayerSignature::new(LayerType::Kindling, hash, path, inputs))
    }

    /// Hash a local compliance report via the injected filesystem.
    async fn hash_report_file(&self, path: &str) -> Result<LayerSignature> {
        let data = self
            .fs
            .read_file(std::path::Path::new(path))
            .await
            .map_err(|e| TameshiError::CollectorError {
                layer: "kindling".to_string(),
                message: format!("failed to read report {path}: {e}"),
            })?;

        let report: serde_json::Value =
            serde_json::from_slice(&data).map_err(|e| TameshiError::CollectorError {
                layer: "kindling".to_string(),
                message: format!("failed to parse report: {e}"),
            })?;

        let canonical = serde_json::to_vec(&report)?;
        let hash = Blake3Hash::digest(&canonical);

        let inputs = vec![InputHash {
            name: "compliance-report".to_string(),
            hash: hash.clone(),
            size_bytes: Some(canonical.len() as u64),
        }];

        Ok(LayerSignature::new(LayerType::Kindling, hash, path, inputs))
    }

    /// Hash identity from a Kubernetes secret via the injected command runner.
    async fn hash_k8s_secret(&self, namespace: &str, secret_name: &str) -> Result<LayerSignature> {
        let output = self
            .cmd
            .run(
                "kubectl",
                &[
                    "get",
                    "secret",
                    secret_name,
                    "-n",
                    namespace,
                    "-o",
                    "jsonpath={.data}",
                ],
            )
            .await
            .map_err(|e| TameshiError::CollectorError {
                layer: "kindling".to_string(),
                message: format!("failed to get secret {namespace}/{secret_name}: {e}"),
            })?;

        let hash = Blake3Hash::digest(output.as_bytes());
        let inputs = vec![InputHash {
            name: format!("{namespace}/{secret_name}"),
            hash: hash.clone(),
            size_bytes: Some(output.len() as u64),
        }];

        debug!(
            namespace = namespace,
            secret_name = secret_name,
            "Hashed Kindling identity from K8s secret (generic)"
        );

        Ok(LayerSignature::new(
            LayerType::Kindling,
            hash,
            &format!("secret:{namespace}/{secret_name}"),
            inputs,
        ))
    }
}

impl<C: CommandRunner, F: FileSystem> LayerCollector for GenericKindlingCollector<C, F> {
    async fn collect(&self) -> Result<LayerSignature> {
        match &self.source {
            GenericKindlingSource::IdentityFile(path) => self.hash_identity_file(path).await,
            GenericKindlingSource::ReportFile(path) => self.hash_report_file(path).await,
            GenericKindlingSource::K8sSecret {
                namespace,
                secret_name,
            } => self.hash_k8s_secret(namespace, secret_name).await,
        }
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Kindling
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute composite hash from sorted input hashes.
#[inline]
fn compute_composite_hash(inputs: &[InputHash]) -> Blake3Hash {
    if inputs.is_empty() {
        return Blake3Hash::digest(b"empty-inputs");
    }
    let mut data = Vec::with_capacity(inputs.len() * 32);
    for input in inputs {
        data.extend_from_slice(&input.hash.0);
    }
    Blake3Hash::digest(&data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{MockCommandRunner, MockFileSystem, MockHttpClient};

    // -- GenericNixCollector tests --

    #[tokio::test]
    async fn generic_nix_collector_hashes_closure() {
        let runner = MockCommandRunner::new();
        runner.add_response(
            "nix-store",
            &["--query", "--requisites", "/nix/store/abc-myapp"],
            "/nix/store/dep1\n/nix/store/dep2\n",
        );
        runner.add_raw_response(
            "nix-store",
            &["--dump", "/nix/store/dep1"],
            b"nar-content-1".to_vec(),
        );
        runner.add_raw_response(
            "nix-store",
            &["--dump", "/nix/store/dep2"],
            b"nar-content-2".to_vec(),
        );

        let collector = GenericNixCollector::new(Some("/nix/store/abc-myapp".to_string()), runner);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Nix);
        assert_eq!(sig.inputs.len(), 2);
        assert_eq!(sig.metadata.source, "/nix/store/abc-myapp");
    }

    #[tokio::test]
    async fn generic_nix_collector_falls_back_on_dump_failure() {
        let runner = MockCommandRunner::new();
        runner.add_response(
            "nix-store",
            &["--query", "--requisites", "/nix/store/xyz"],
            "/nix/store/only-path\n",
        );
        // Don't register a --dump response, so it will fail and fall back

        let collector = GenericNixCollector::new(Some("/nix/store/xyz".to_string()), runner);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.inputs.len(), 1);
        // Should hash the path string as fallback
        assert_eq!(
            sig.inputs[0].hash,
            Blake3Hash::digest(b"/nix/store/only-path")
        );
    }

    #[tokio::test]
    async fn generic_nix_collector_errors_without_store_path() {
        let runner = MockCommandRunner::new();
        let collector = GenericNixCollector::new(None, runner);
        let result = collector.collect().await;
        assert!(result.is_err());
    }

    // -- GenericOciCollector tests --

    #[tokio::test]
    async fn generic_oci_collector_hashes_manifest() {
        let runner = MockCommandRunner::new();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "layers": [
                {"digest": "sha256:abc123", "size": 1024},
                {"digest": "sha256:def456", "size": 2048}
            ],
            "config": {"digest": "sha256:cfg789", "size": 512}
        });
        runner.add_raw_response(
            "skopeo",
            &["inspect", "--raw", "docker://ghcr.io/org/app:latest"],
            serde_json::to_vec(&manifest).unwrap(),
        );

        let collector = GenericOciCollector::new("ghcr.io/org/app:latest", runner);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Oci);
        assert_eq!(sig.inputs.len(), 3); // 2 layers + 1 config
    }

    // -- GenericKubernetesCollector tests --

    #[tokio::test]
    async fn generic_k8s_collector_hashes_namespace() {
        let runner = MockCommandRunner::new();

        // Register responses for the resource types we want to find
        let deployments = serde_json::json!({
            "items": [{
                "metadata": {
                    "name": "my-app",
                    "namespace": "default",
                    "resourceVersion": "123",
                    "uid": "abc"
                },
                "spec": {"replicas": 2}
            }]
        });
        runner.add_response(
            "kubectl",
            &["get", "deployments", "-n", "test-ns", "-o", "json"],
            &serde_json::to_string(&deployments).unwrap(),
        );

        // Other resource types return errors (not found)
        // The collector handles these gracefully

        let collector = GenericKubernetesCollector::new("test-ns", runner);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Kubernetes);
        // Only deployments were successful
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "test-ns/deployments");
    }

    // -- GenericTataraApiCollector tests --

    #[tokio::test]
    async fn generic_tatara_api_collector() {
        let client = MockHttpClient::new();
        let state = serde_json::json!({
            "nodes": [{"id": "node-1"}, {"id": "node-2"}],
            "allocations": []
        });
        client.add_json_response("https://tatara.local/api/v1/state", &state);

        let collector = GenericTataraApiCollector::new("https://tatara.local", client);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Tatara);
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "cluster-state-api");
    }

    // -- GenericTofuCollector tests --

    #[tokio::test]
    async fn generic_tofu_plan_collector() {
        let runner = MockCommandRunner::new();
        let plan_json = serde_json::json!({
            "format_version": "1.0",
            "resource_changes": []
        });
        runner.add_response(
            "tofu",
            &["show", "-json", "/path/to/plan.tfplan"],
            &serde_json::to_string(&plan_json).unwrap(),
        );

        let collector = GenericTofuCollector::from_plan("/path/to/plan.tfplan", runner);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Tofu);
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "plan");
    }

    #[tokio::test]
    async fn generic_tofu_remote_state_collector() {
        let runner = MockCommandRunner::new();
        let state_json = serde_json::json!({
            "version": 4,
            "resources": [{"type": "aws_instance", "name": "web"}]
        });
        runner.add_response(
            "tofu",
            &["state", "pull"],
            &serde_json::to_string(&state_json).unwrap(),
        );

        let collector = GenericTofuCollector::from_remote("/infra/project", runner);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Tofu);
    }

    // -- GenericHelmCollector tests --

    #[tokio::test]
    async fn generic_helm_collector_hashes_chart() {
        let fs = MockFileSystem::new();

        let chart_yaml = b"apiVersion: v2\nname: my-chart\nversion: 0.1.0";
        let values_yaml = b"replicas: 2\nimage: ghcr.io/org/app:latest";
        let template1 = b"apiVersion: apps/v1\nkind: Deployment";
        let template2 = b"apiVersion: v1\nkind: Service";

        fs.add_file("/charts/my-chart/Chart.yaml", chart_yaml.to_vec());
        fs.add_file("/charts/my-chart/values.yaml", values_yaml.to_vec());
        fs.add_dir(
            std::path::PathBuf::from("/charts/my-chart/templates"),
            vec![
                std::path::PathBuf::from("/charts/my-chart/templates/deployment.yaml"),
                std::path::PathBuf::from("/charts/my-chart/templates/service.yaml"),
            ],
        );
        fs.add_file(
            "/charts/my-chart/templates/deployment.yaml",
            template1.to_vec(),
        );
        fs.add_file(
            "/charts/my-chart/templates/service.yaml",
            template2.to_vec(),
        );

        let collector = GenericHelmCollector::new("/charts/my-chart", fs);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Helm);
        // Chart.yaml + values.yaml + 2 templates = 4
        assert_eq!(sig.inputs.len(), 4);
    }

    #[tokio::test]
    async fn generic_helm_collector_empty_chart() {
        let fs = MockFileSystem::new();
        let collector = GenericHelmCollector::new("/nonexistent-chart", fs);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Helm);
        assert!(sig.inputs.is_empty());
    }

    // -- GenericFluxCDCollector tests --

    #[tokio::test]
    async fn generic_fluxcd_collector_hashes_namespace() {
        let runner = MockCommandRunner::new();

        let kustomizations = serde_json::json!({
            "items": [{
                "metadata": {
                    "name": "my-app",
                    "namespace": "flux-system",
                    "resourceVersion": "456",
                    "uid": "flux-uid"
                },
                "spec": {"interval": "5m", "path": "./k8s"},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]}
            }]
        });
        runner.add_response(
            "kubectl",
            &[
                "get",
                "kustomizations.kustomize.toolkit.fluxcd.io",
                "-n",
                "flux-system",
                "-o",
                "json",
            ],
            &serde_json::to_string(&kustomizations).unwrap(),
        );

        // Other resource types return errors (not found)

        let collector = GenericFluxCDCollector::new("flux-system", runner);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::FluxCD);
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(
            sig.inputs[0].name,
            "flux-system/kustomizations.kustomize.toolkit.fluxcd.io"
        );
    }

    #[tokio::test]
    async fn generic_fluxcd_collector_strips_volatile_fields() {
        let runner = MockCommandRunner::new();

        let resources = serde_json::json!({
            "items": [{
                "metadata": {
                    "name": "app",
                    "resourceVersion": "999",
                    "uid": "test-uid",
                    "creationTimestamp": "2026-01-01T00:00:00Z",
                    "managedFields": [],
                    "generation": 3
                },
                "spec": {"interval": "10m"},
                "status": {"lastHandledReconcileAt": "2026-03-19T10:00:00Z"}
            }]
        });
        runner.add_response(
            "kubectl",
            &[
                "get",
                "kustomizations.kustomize.toolkit.fluxcd.io",
                "-n",
                "test-ns",
                "-o",
                "json",
            ],
            &serde_json::to_string(&resources).unwrap(),
        );

        let collector = GenericFluxCDCollector::new("test-ns", runner);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.inputs.len(), 1);

        // Verify the hash is deterministic (volatile fields stripped)
        let collector2_runner = MockCommandRunner::new();
        let resources2 = serde_json::json!({
            "items": [{
                "metadata": {
                    "name": "app",
                    "resourceVersion": "1000",  // different version
                    "uid": "different-uid",
                    "creationTimestamp": "2026-02-01T00:00:00Z",
                    "managedFields": [{"manager": "flux"}],
                    "generation": 5
                },
                "spec": {"interval": "10m"},
                "status": {"lastHandledReconcileAt": "2026-03-19T12:00:00Z"}
            }]
        });
        collector2_runner.add_response(
            "kubectl",
            &[
                "get",
                "kustomizations.kustomize.toolkit.fluxcd.io",
                "-n",
                "test-ns",
                "-o",
                "json",
            ],
            &serde_json::to_string(&resources2).unwrap(),
        );

        let collector2 = GenericFluxCDCollector::new("test-ns", collector2_runner);
        let sig2 = collector2.collect().await.unwrap();
        // Same spec, different volatile fields => same hash
        assert_eq!(sig.inputs[0].hash, sig2.inputs[0].hash);
    }

    #[tokio::test]
    async fn generic_fluxcd_collector_empty_namespace() {
        let runner = MockCommandRunner::new();
        // All resource types return errors (nothing registered)
        let collector = GenericFluxCDCollector::new("empty-ns", runner);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::FluxCD);
        assert!(sig.inputs.is_empty());
    }

    // -- GenericArgoCDCollector tests --

    #[tokio::test]
    async fn generic_argocd_collector_hashes_namespace() {
        let runner = MockCommandRunner::new();

        let applications = serde_json::json!({
            "items": [{
                "metadata": {
                    "name": "my-app",
                    "namespace": "argocd",
                    "resourceVersion": "789",
                    "uid": "argo-uid"
                },
                "spec": {
                    "source": {
                        "repoURL": "https://github.com/org/repo",
                        "targetRevision": "main",
                        "path": "k8s"
                    },
                    "destination": {
                        "server": "https://kubernetes.default.svc",
                        "namespace": "default"
                    }
                },
                "status": {
                    "sync": {"status": "Synced"},
                    "health": {"status": "Healthy"}
                }
            }]
        });
        runner.add_response(
            "kubectl",
            &[
                "get",
                "applications.argoproj.io",
                "-n",
                "argocd",
                "-o",
                "json",
            ],
            &serde_json::to_string(&applications).unwrap(),
        );

        let collector = GenericArgoCDCollector::new("argocd", runner);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::ArgoCD);
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "argocd/applications.argoproj.io");
    }

    #[tokio::test]
    async fn generic_argocd_collector_strips_volatile_fields() {
        let runner = MockCommandRunner::new();

        let resources = serde_json::json!({
            "items": [{
                "metadata": {
                    "name": "app",
                    "resourceVersion": "100",
                    "uid": "uid-1",
                    "creationTimestamp": "2026-01-01T00:00:00Z",
                    "managedFields": [],
                    "generation": 2
                },
                "spec": {
                    "source": {"repoURL": "https://github.com/org/repo"}
                },
                "status": {"sync": {"status": "OutOfSync"}},
                "operation": {"sync": {"revision": "abc"}}
            }]
        });
        runner.add_response(
            "kubectl",
            &[
                "get",
                "applications.argoproj.io",
                "-n",
                "argocd",
                "-o",
                "json",
            ],
            &serde_json::to_string(&resources).unwrap(),
        );

        let collector = GenericArgoCDCollector::new("argocd", runner);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.inputs.len(), 1);

        // Verify same spec with different volatile fields produces same hash
        let runner2 = MockCommandRunner::new();
        let resources2 = serde_json::json!({
            "items": [{
                "metadata": {
                    "name": "app",
                    "resourceVersion": "200",
                    "uid": "uid-2",
                    "creationTimestamp": "2026-02-01T00:00:00Z",
                    "managedFields": [{"manager": "argocd"}],
                    "generation": 5
                },
                "spec": {
                    "source": {"repoURL": "https://github.com/org/repo"}
                },
                "status": {"sync": {"status": "Synced"}},
                "operation": {"sync": {"revision": "def"}}
            }]
        });
        runner2.add_response(
            "kubectl",
            &[
                "get",
                "applications.argoproj.io",
                "-n",
                "argocd",
                "-o",
                "json",
            ],
            &serde_json::to_string(&resources2).unwrap(),
        );

        let collector2 = GenericArgoCDCollector::new("argocd", runner2);
        let sig2 = collector2.collect().await.unwrap();
        assert_eq!(sig.inputs[0].hash, sig2.inputs[0].hash);
    }

    #[tokio::test]
    async fn generic_argocd_collector_empty_namespace() {
        let runner = MockCommandRunner::new();
        let collector = GenericArgoCDCollector::new("empty-ns", runner);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::ArgoCD);
        assert!(sig.inputs.is_empty());
    }

    // -- Determinism tests --

    #[tokio::test]
    async fn generic_nix_collector_deterministic() {
        async fn make_sig() -> LayerSignature {
            let runner = MockCommandRunner::new();
            runner.add_response(
                "nix-store",
                &["--query", "--requisites", "/nix/store/test"],
                "/nix/store/a\n/nix/store/b\n",
            );
            runner.add_raw_response(
                "nix-store",
                &["--dump", "/nix/store/a"],
                b"content-a".to_vec(),
            );
            runner.add_raw_response(
                "nix-store",
                &["--dump", "/nix/store/b"],
                b"content-b".to_vec(),
            );
            let collector = GenericNixCollector::new(Some("/nix/store/test".to_string()), runner);
            collector.collect().await.unwrap()
        }

        let sig1 = make_sig().await;
        let sig2 = make_sig().await;
        assert_eq!(sig1.hash, sig2.hash);
        assert_eq!(sig1.inputs.len(), sig2.inputs.len());
    }

    #[tokio::test]
    async fn generic_helm_collector_deterministic() {
        async fn make_sig() -> LayerSignature {
            let fs = MockFileSystem::new();
            fs.add_file("/chart/Chart.yaml", b"name: test".to_vec());
            fs.add_file("/chart/values.yaml", b"key: val".to_vec());
            let collector = GenericHelmCollector::new("/chart", fs);
            collector.collect().await.unwrap()
        }

        let sig1 = make_sig().await;
        let sig2 = make_sig().await;
        assert_eq!(sig1.hash, sig2.hash);
    }

    // -- GenericKindlingCollector tests --

    #[tokio::test]
    async fn generic_kindling_identity_file() {
        let runner = MockCommandRunner::new();
        let fs = MockFileSystem::new();

        let identity = serde_json::json!({
            "cluster_id": "test-cluster",
            "certificates": [
                {"cn": "cluster-ca", "pem": "-----BEGIN CERTIFICATE-----"},
                {"cn": "apiserver", "pem": "-----BEGIN CERTIFICATE-----"}
            ]
        });
        fs.add_file(
            "/etc/kindling/identity.json",
            serde_json::to_vec(&identity).unwrap(),
        );

        let collector =
            GenericKindlingCollector::from_identity("/etc/kindling/identity.json", runner, fs);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Kindling);
        // identity-document + 2 certificates = 3 inputs
        assert_eq!(sig.inputs.len(), 3);
        assert_eq!(sig.inputs[0].name, "identity-document");
        assert_eq!(sig.inputs[1].name, "certificate-0");
        assert_eq!(sig.inputs[2].name, "certificate-1");
    }

    #[tokio::test]
    async fn generic_kindling_identity_no_certificates() {
        let runner = MockCommandRunner::new();
        let fs = MockFileSystem::new();

        let identity = serde_json::json!({
            "cluster_id": "minimal-cluster"
        });
        fs.add_file(
            "/etc/kindling/identity.json",
            serde_json::to_vec(&identity).unwrap(),
        );

        let collector =
            GenericKindlingCollector::from_identity("/etc/kindling/identity.json", runner, fs);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Kindling);
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "identity-document");
    }

    #[tokio::test]
    async fn generic_kindling_report_file() {
        let runner = MockCommandRunner::new();
        let fs = MockFileSystem::new();

        let report = serde_json::json!({
            "status": "compliant",
            "checks": [
                {"name": "cis-1.1", "passed": true},
                {"name": "cis-1.2", "passed": true}
            ]
        });
        fs.add_file(
            "/var/kindling/report.json",
            serde_json::to_vec(&report).unwrap(),
        );

        let collector =
            GenericKindlingCollector::from_report("/var/kindling/report.json", runner, fs);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Kindling);
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "compliance-report");
    }

    #[tokio::test]
    async fn generic_kindling_k8s_secret() {
        let runner = MockCommandRunner::new();
        let fs = MockFileSystem::new();

        runner.add_response(
            "kubectl",
            &[
                "get",
                "secret",
                "kindling-identity",
                "-n",
                "kindling-system",
                "-o",
                "jsonpath={.data}",
            ],
            r#"{"identity.json":"base64encodeddata"}"#,
        );

        let collector = GenericKindlingCollector::from_k8s_secret(
            "kindling-system",
            "kindling-identity",
            runner,
            fs,
        );
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Kindling);
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "kindling-system/kindling-identity");
        assert_eq!(
            sig.metadata.source,
            "secret:kindling-system/kindling-identity"
        );
    }

    #[tokio::test]
    async fn generic_kindling_k8s_secret_failure() {
        let runner = MockCommandRunner::new();
        let fs = MockFileSystem::new();
        // No response registered -> command fails

        let collector = GenericKindlingCollector::from_k8s_secret(
            "kindling-system",
            "nonexistent-secret",
            runner,
            fs,
        );
        let result = collector.collect().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn generic_kindling_identity_missing_file() {
        let runner = MockCommandRunner::new();
        let fs = MockFileSystem::new();
        // No file registered -> read fails

        let collector =
            GenericKindlingCollector::from_identity("/nonexistent/identity.json", runner, fs);
        let result = collector.collect().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn generic_kindling_identity_deterministic() {
        async fn make_sig() -> LayerSignature {
            let runner = MockCommandRunner::new();
            let fs = MockFileSystem::new();
            let identity = serde_json::json!({"cluster_id": "stable"});
            fs.add_file("/identity.json", serde_json::to_vec(&identity).unwrap());
            let collector = GenericKindlingCollector::from_identity("/identity.json", runner, fs);
            collector.collect().await.unwrap()
        }

        let sig1 = make_sig().await;
        let sig2 = make_sig().await;
        assert_eq!(sig1.hash, sig2.hash);
        assert_eq!(sig1.inputs.len(), sig2.inputs.len());
    }

    #[tokio::test]
    async fn generic_kindling_layer_type() {
        let runner = MockCommandRunner::new();
        let fs = MockFileSystem::new();
        let collector = GenericKindlingCollector::from_identity("/identity.json", runner, fs);
        assert_eq!(collector.layer_type(), LayerType::Kindling);
    }
}
