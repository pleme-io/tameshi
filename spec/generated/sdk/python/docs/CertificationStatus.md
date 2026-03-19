# CertificationStatus

Observed state of a Certification

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**phase** | [**CertPhase**](CertPhase.md) |  | 
**master_signature** | **str** | Composite master signature across all gates | [optional] 
**compliance_signature** | **str** | BLAKE3 hash of the compliance assessment result | [optional] 
**secure_signature** | **str** | BLAKE3 hash combining master and compliance signatures | [optional] 
**last_certified_at** | **datetime** | Timestamp of the last successful certification | [optional] 
**gate_statuses** | [**List[GateStatusRef]**](GateStatusRef.md) | Status of each gate included in this certification | [optional] 
**audit_trail** | [**List[AuditEntry]**](AuditEntry.md) | Ordered audit trail for this certification | [optional] 

## Example

```python
from tameshi_client.models.certification_status import CertificationStatus

# TODO update the JSON string below
json = "{}"
# create an instance of CertificationStatus from a JSON string
certification_status_instance = CertificationStatus.from_json(json)
# print the JSON string representation of the object
print(CertificationStatus.to_json())

# convert the object into a dict
certification_status_dict = certification_status_instance.to_dict()
# create an instance of CertificationStatus from a dict
certification_status_from_dict = CertificationStatus.from_dict(certification_status_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


