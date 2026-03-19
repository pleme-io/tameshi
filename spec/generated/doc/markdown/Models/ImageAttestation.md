# ImageAttestation
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **imageRef** | **String** | Full image reference (registry/repo) | [default to null] |
| **tag** | **String** | Image tag | [default to null] |
| **architecture** | **String** | Target CPU architecture (e.g. amd64, arm64) | [default to null] |
| **manifestHash** | **String** | OCI manifest digest | [default to null] |
| **cosignVerified** | **Boolean** | Whether the image signature was verified with cosign | [default to null] |
| **signerIdentity** | **String** | Identity of the cosign signer | [optional] [default to null] |
| **vulnScanHash** | **String** | BLAKE3 hash of vulnerability scan results | [optional] [default to null] |
| **vulnCount** | **Integer** | Total number of vulnerabilities found | [optional] [default to null] |
| **criticalHighVulns** | **Integer** | Number of critical and high severity vulnerabilities | [optional] [default to null] |
| **sbomHash** | **String** | BLAKE3 hash of the image SBOM | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

