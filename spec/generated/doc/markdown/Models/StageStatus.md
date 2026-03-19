# StageStatus
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **stage** | **String** | Stage name (e.g. source, build, image, chart, deployment) | [default to null] |
| **passed** | **Boolean** | Whether the stage passed | [default to null] |
| **hash** | **String** | BLAKE3 hash of the stage attestation data | [default to null] |
| **violations** | **List** | Policy violations found in this stage | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

