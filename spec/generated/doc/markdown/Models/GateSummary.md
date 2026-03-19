# GateSummary
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **name** | **String** | Name of the SignatureGate resource | [default to null] |
| **namespace** | **String** | Kubernetes namespace | [default to null] |
| **phase** | [**GatePhase**](GatePhase.md) |  | [default to null] |
| **layers** | [**List**](LayerType.md) | Infrastructure layers this gate covers | [default to null] |
| **expectedSignature** | **String** | Expected composite signature | [optional] [default to null] |
| **currentSignature** | **String** | Most recently computed composite signature | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

