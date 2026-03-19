# CertificationPolicy
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **name** | **String** | Policy name | [default to null] |
| **requireSignedCommits** | **Boolean** | Require all commits to be GPG/SSH signed | [optional] [default to null] |
| **requirePinnedInputs** | **Boolean** | Require all Nix flake inputs to be pinned | [optional] [default to null] |
| **minSlsaLevel** | [**SlsaLevel**](SlsaLevel.md) |  | [optional] [default to null] |
| **requireReproducible** | **Boolean** | Require builds to be reproducible | [optional] [default to null] |
| **maxCriticalHighCves** | **Integer** | Maximum allowed critical+high CVEs across all builds | [optional] [default to null] |
| **requireImageSignatures** | **Boolean** | Require all container images to have cosign signatures | [optional] [default to null] |
| **requireChartProvenance** | **Boolean** | Require Helm chart provenance verification | [optional] [default to null] |
| **requireSourceVerification** | **Boolean** | Require source commit signature verification | [optional] [default to null] |
| **minCisPassRate** | **Float** | Minimum CIS Kubernetes benchmark pass rate (0.0 to 1.0) | [optional] [default to null] |
| **requireNetworkPolicies** | **Boolean** | Require NetworkPolicy resources for all namespaces | [optional] [default to null] |
| **requireCompliance** | **Boolean** | Require compliance assessment to pass | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

