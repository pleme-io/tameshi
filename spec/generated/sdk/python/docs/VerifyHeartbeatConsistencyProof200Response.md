# VerifyHeartbeatConsistencyProof200Response


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**verified** | **bool** | Whether the consistency proof is valid | 
**error** | **str** | Error message if verification failed | [optional] 

## Example

```python
from tameshi_client.models.verify_heartbeat_consistency_proof200_response import VerifyHeartbeatConsistencyProof200Response

# TODO update the JSON string below
json = "{}"
# create an instance of VerifyHeartbeatConsistencyProof200Response from a JSON string
verify_heartbeat_consistency_proof200_response_instance = VerifyHeartbeatConsistencyProof200Response.from_json(json)
# print the JSON string representation of the object
print(VerifyHeartbeatConsistencyProof200Response.to_json())

# convert the object into a dict
verify_heartbeat_consistency_proof200_response_dict = verify_heartbeat_consistency_proof200_response_instance.to_dict()
# create an instance of VerifyHeartbeatConsistencyProof200Response from a dict
verify_heartbeat_consistency_proof200_response_from_dict = VerifyHeartbeatConsistencyProof200Response.from_dict(verify_heartbeat_consistency_proof200_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


