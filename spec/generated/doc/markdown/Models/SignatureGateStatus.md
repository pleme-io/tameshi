# SignatureGateStatus
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **phase** | [**GatePhase**](GatePhase.md) |  | [default to null] |
| **currentSignature** | **String** | Most recently computed composite signature | [optional] [default to null] |
| **lastVerifiedAt** | **Date** | Timestamp of the last successful verification | [optional] [default to null] |
| **layerStatuses** | [**List**](LayerStatus.md) | Per-layer verification status | [optional] [default to null] |
| **message** | **String** | Human-readable status message | [optional] [default to null] |
| **failureCount** | **Integer** | Number of consecutive verification failures | [optional] [default to null] |
| **admissionDecisions** | [**AdmissionDecisionCounts**](AdmissionDecisionCounts.md) |  | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

