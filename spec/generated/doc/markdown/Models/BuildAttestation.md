# BuildAttestation
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **service** | **String** | Name of the service that was built | [default to null] |
| **derivation** | **String** | Nix store derivation path | [default to null] |
| **closureHash** | **String** | BLAKE3 hash of the Nix closure | [default to null] |
| **slsaLevel** | [**SlsaLevel**](SlsaLevel.md) |  | [default to null] |
| **reproducible** | **Boolean** | Whether the build is reproducible | [default to null] |
| **hermetic** | **Boolean** | Whether the build is hermetic (no network access) | [default to null] |
| **sbomHash** | **String** | BLAKE3 hash of the software bill of materials | [optional] [default to null] |
| **vulnScanHash** | **String** | BLAKE3 hash of vulnerability scan results | [optional] [default to null] |
| **cveCount** | **Integer** | Total number of CVEs found | [optional] [default to null] |
| **criticalHighCves** | **Integer** | Number of critical and high severity CVEs | [optional] [default to null] |
| **builder** | **String** | Builder identity (e.g. nix, bazel) | [optional] [default to null] |
| **builtAt** | **Date** | Timestamp when the build completed | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

