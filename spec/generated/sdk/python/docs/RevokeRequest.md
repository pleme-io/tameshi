# RevokeRequest

Request to revoke a compromised hash across all nodes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**hash** | **str** | BLAKE3 hash in prefixed hex format | 
**reason** | **str** | CVE identifier or reason for revocation (e.g. CVE-2026-XXXX) | 
**severity** | **str** | Severity of the incident | 
**operator** | **str** | Identity of the operator performing the revocation (e.g. email) | 

## Example

```python
from tameshi_client.models.revoke_request import RevokeRequest

# TODO update the JSON string below
json = "{}"
# create an instance of RevokeRequest from a JSON string
revoke_request_instance = RevokeRequest.from_json(json)
# print the JSON string representation of the object
print(RevokeRequest.to_json())

# convert the object into a dict
revoke_request_dict = revoke_request_instance.to_dict()
# create an instance of RevokeRequest from a dict
revoke_request_from_dict = RevokeRequest.from_dict(revoke_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


