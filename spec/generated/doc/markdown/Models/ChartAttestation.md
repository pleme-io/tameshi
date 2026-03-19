# ChartAttestation
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **chartName** | **String** | Helm chart name | [default to null] |
| **chartVersion** | **String** | Helm chart version | [default to null] |
| **chartHash** | **String** | BLAKE3 hash of the packaged chart | [default to null] |
| **provenanceVerified** | **Boolean** | Whether the chart provenance file was verified | [default to null] |
| **dependencyHashes** | **List** | BLAKE3 hashes of chart dependencies | [optional] [default to null] |
| **linterPassed** | **Boolean** | Whether the chart passed helm lint | [default to null] |
| **policyPassed** | **Boolean** | Whether the chart passed OPA/Kyverno policies | [default to null] |
| **registryRef** | **String** | OCI registry reference for the chart | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

