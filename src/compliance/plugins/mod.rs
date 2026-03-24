//! Domain-specific compliance plugins.
//!
//! Each plugin evaluates controls for a specific infrastructure domain:
//!
//! | Plugin | Domain | Description |
//! |--------|--------|-------------|
//! | [`agent_layer::AgentLayerPlugin`] | `agent-attestation` | Agent layer attestation (MCP, deps, certs) |
//! | [`kernel::KernelPlugin`] | `kernel` | Linux kernel hardening (sysctl, modules, MAC) |
//! | [`nix_store::NixStorePlugin`] | `nix-store` | Nix store integrity and pinning |
//! | [`oci::OciPlugin`] | `oci` | OCI container security |
//! | [`kubernetes::KubernetesPlugin`] | `kubernetes` | Kubernetes cluster security |
//! | [`mock::MockPlugin`] | (configurable) | Testing mock |

pub mod agent_layer;
pub mod kernel;
pub mod kubernetes;
pub mod mock;
pub mod nix_store;
pub mod oci;
