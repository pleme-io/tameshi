# ComplianceAttestation
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **environment** | **String** | Environment being attested | [default to null] |
| **artifact** | **String** | Artifact identifier being attested | [default to null] |
| **dimensions** | [**List**](ComplianceDimension.md) | Individual compliance dimensions assessed | [default to null] |
| **complianceHash** | **String** | BLAKE3 hash of all dimension results combined | [default to null] |
| **computedAt** | **Date** | When the attestation was computed | [default to null] |
| **policyName** | **String** | Name of the policy applied | [default to null] |
| **allPassed** | **Boolean** | Whether all required dimensions passed | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

