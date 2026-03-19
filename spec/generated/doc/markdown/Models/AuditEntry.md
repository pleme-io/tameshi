# AuditEntry
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **timestamp** | **Date** | When the audit event occurred | [default to null] |
| **action** | [**AuditAction**](AuditAction.md) |  | [default to null] |
| **signature** | **String** | Signature associated with this audit event | [default to null] |
| **details** | **String** | Human-readable details about the event | [optional] [default to null] |
| **resource** | **String** | Kubernetes resource involved (e.g. apps/v1/Deployment/my-app) | [optional] [default to null] |
| **allowed** | **Boolean** | Whether the operation was allowed (for admission events) | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

