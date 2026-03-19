# CertificationStatus
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **phase** | [**CertPhase**](CertPhase.md) |  | [default to null] |
| **masterSignature** | **String** | Composite master signature across all gates | [optional] [default to null] |
| **complianceSignature** | **String** | BLAKE3 hash of the compliance assessment result | [optional] [default to null] |
| **secureSignature** | **String** | BLAKE3 hash combining master and compliance signatures | [optional] [default to null] |
| **lastCertifiedAt** | **Date** | Timestamp of the last successful certification | [optional] [default to null] |
| **gateStatuses** | [**List**](GateStatusRef.md) | Status of each gate included in this certification | [optional] [default to null] |
| **auditTrail** | [**List**](AuditEntry.md) | Ordered audit trail for this certification | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

