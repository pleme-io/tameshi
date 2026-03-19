# ComplianceResult
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **id** | **String** | Unique identifier for this compliance result | [default to null] |
| **environment** | **String** | Environment that was assessed | [default to null] |
| **baseline** | [**ComplianceBaseline**](ComplianceBaseline.md) |  | [default to null] |
| **frameworkHash** | **String** | BLAKE3 hash of the compliance framework definition | [default to null] |
| **catalogHash** | **String** | BLAKE3 hash of the control catalog | [default to null] |
| **assessmentResult** | [**Object**](.md) | Full OSCAL assessment result object | [default to null] |
| **complianceHash** | **String** | BLAKE3 hash of the entire assessment result | [default to null] |
| **allSatisfied** | **Boolean** | Whether all controls are satisfied | [default to null] |
| **computedAt** | **Date** | When the result was computed | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

