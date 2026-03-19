# LayerStatus
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **layer** | [**LayerType**](LayerType.md) |  | [default to null] |
| **hash** | **String** | Computed BLAKE3 hash for this layer | [default to null] |
| **verified** | **Boolean** | Whether the layer hash matches the expected value | [default to null] |
| **lastVerifiedAt** | **Date** | Timestamp of the last verification for this layer | [optional] [default to null] |
| **error** | **String** | Error message if verification failed | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

