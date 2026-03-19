# ResultSummary
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **id** | **String** | Unique identifier for this compliance result | [default to null] |
| **environment** | **String** | Environment that was assessed | [default to null] |
| **baseline** | [**ComplianceBaseline**](ComplianceBaseline.md) |  | [default to null] |
| **complianceHash** | **String** | BLAKE3 hash of the assessment result | [default to null] |
| **allSatisfied** | **Boolean** | Whether all controls are satisfied | [default to null] |
| **totalControls** | **Integer** | Total number of controls assessed | [default to null] |
| **satisfied** | **Integer** | Number of satisfied controls | [default to null] |
| **notSatisfied** | **Integer** | Number of unsatisfied controls | [default to null] |
| **performedAt** | **Date** | When the assessment was performed | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

