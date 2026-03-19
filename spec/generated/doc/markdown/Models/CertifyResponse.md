# CertifyResponse
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **certified** | **Boolean** | Whether the product passed certification | [default to null] |
| **certificationHash** | **String** | Deterministic BLAKE3 hash of the entire certification | [default to null] |
| **complianceHash** | **String** | BLAKE3 hash of the compliance dimension | [optional] [default to null] |
| **stages** | [**List**](StageStatus.md) | Result for each pipeline stage | [default to null] |
| **violations** | **List** | List of policy violations found | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

