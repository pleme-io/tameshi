# CertificationSummary
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **name** | **String** | Name of the Certification resource | [default to null] |
| **namespace** | **String** | Kubernetes namespace | [default to null] |
| **environment** | **String** | Target environment (e.g. plo, zek) | [default to null] |
| **phase** | [**CertPhase**](CertPhase.md) |  | [default to null] |
| **gates** | **List** | Names of the SignatureGates included in this certification | [optional] [default to null] |
| **masterSignature** | **String** | Composite master signature across all gates | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

