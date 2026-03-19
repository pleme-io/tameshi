# AuditEntry

Single entry in the audit trail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**timestamp** | **datetime** | When the audit event occurred | 
**action** | [**AuditAction**](AuditAction.md) |  | 
**signature** | **str** | Signature associated with this audit event | 
**details** | **str** | Human-readable details about the event | [optional] 
**resource** | **str** | Kubernetes resource involved (e.g. apps/v1/Deployment/my-app) | [optional] 
**allowed** | **bool** | Whether the operation was allowed (for admission events) | [optional] 

## Example

```python
from tameshi_client.models.audit_entry import AuditEntry

# TODO update the JSON string below
json = "{}"
# create an instance of AuditEntry from a JSON string
audit_entry_instance = AuditEntry.from_json(json)
# print the JSON string representation of the object
print(AuditEntry.to_json())

# convert the object into a dict
audit_entry_dict = audit_entry_instance.to_dict()
# create an instance of AuditEntry from a dict
audit_entry_from_dict = AuditEntry.from_dict(audit_entry_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


