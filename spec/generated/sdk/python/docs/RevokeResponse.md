# RevokeResponse

Result of a hash revocation operation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**revoked** | **bool** | Whether the revocation was successfully applied | 
**affected_nodes** | **int** | Number of nodes where the hash was revoked | 
**bpf_maps_updated** | **bool** | Whether kanshi BPF allow-maps were updated on all affected nodes | 
**heartbeat_entry_sequence** | **int** | Sequence number of the Revocation event in the HeartbeatChain | 

## Example

```python
from tameshi_client.models.revoke_response import RevokeResponse

# TODO update the JSON string below
json = "{}"
# create an instance of RevokeResponse from a JSON string
revoke_response_instance = RevokeResponse.from_json(json)
# print the JSON string representation of the object
print(RevokeResponse.to_json())

# convert the object into a dict
revoke_response_dict = revoke_response_instance.to_dict()
# create an instance of RevokeResponse from a dict
revoke_response_from_dict = RevokeResponse.from_dict(revoke_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


