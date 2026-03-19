# GateVerifyResult
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **name** | **String** | Name of the verified gate | [default to null] |
| **verified** | **Boolean** | Whether the gate passed verification | [default to null] |
| **phase** | [**GatePhase**](GatePhase.md) |  | [default to null] |
| **expectedSignature** | **String** | The expected composite signature | [optional] [default to null] |
| **currentSignature** | **String** | The freshly computed composite signature | [optional] [default to null] |
| **layerStatuses** | [**List**](LayerStatus.md) | Per-layer verification results | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

