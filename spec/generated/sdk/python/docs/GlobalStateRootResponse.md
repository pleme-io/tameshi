# GlobalStateRootResponse

Global state root aggregating all cluster roots

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**root_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**cluster_roots** | [**Dict[str, ClusterRootEntry]**](ClusterRootEntry.md) | Per-cluster state, keyed by cluster_id | 
**computed_at** | **datetime** | When this global root was computed | 
**sequence** | **int** | Monotonically increasing sequence number | 
**previous_root** | **str** | BLAKE3 hash in prefixed hex format | 

## Example

```python
from tameshi_client.models.global_state_root_response import GlobalStateRootResponse

# TODO update the JSON string below
json = "{}"
# create an instance of GlobalStateRootResponse from a JSON string
global_state_root_response_instance = GlobalStateRootResponse.from_json(json)
# print the JSON string representation of the object
print(GlobalStateRootResponse.to_json())

# convert the object into a dict
global_state_root_response_dict = global_state_root_response_instance.to_dict()
# create an instance of GlobalStateRootResponse from a dict
global_state_root_response_from_dict = GlobalStateRootResponse.from_dict(global_state_root_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


