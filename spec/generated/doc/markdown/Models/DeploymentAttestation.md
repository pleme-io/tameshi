# DeploymentAttestation
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **namespace** | **String** | Kubernetes namespace | [default to null] |
| **kustomization** | **String** | FluxCD Kustomization name | [default to null] |
| **sourceCommit** | **String** | Git commit the deployment was sourced from | [default to null] |
| **sourceVerified** | **Boolean** | Whether the source commit signature was verified | [default to null] |
| **manifestHash** | **String** | BLAKE3 hash of rendered Kubernetes manifests | [default to null] |
| **allReleasesSigned** | **Boolean** | Whether all HelmRelease resources have verified signatures | [default to null] |
| **cisK8sPassRate** | **Float** | CIS Kubernetes benchmark pass rate (0.0 to 1.0) | [optional] [default to null] |
| **networkPoliciesVerified** | **Boolean** | Whether required NetworkPolicy resources are in place | [default to null] |
| **runningPods** | **Integer** | Number of running pods in the deployment | [default to null] |
| **allHealthy** | **Boolean** | Whether all pods are in healthy state | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

