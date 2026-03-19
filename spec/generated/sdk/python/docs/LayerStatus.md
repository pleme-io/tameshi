# LayerStatus

Verification status for a single infrastructure layer

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**layer** | [**LayerType**](LayerType.md) |  | 
**hash** | **str** | Computed BLAKE3 hash for this layer | 
**verified** | **bool** | Whether the layer hash matches the expected value | 
**last_verified_at** | **datetime** | Timestamp of the last verification for this layer | [optional] 
**error** | **str** | Error message if verification failed | [optional] 

## Example

```python
from tameshi_client.models.layer_status import LayerStatus

# TODO update the JSON string below
json = "{}"
# create an instance of LayerStatus from a JSON string
layer_status_instance = LayerStatus.from_json(json)
# print the JSON string representation of the object
print(LayerStatus.to_json())

# convert the object into a dict
layer_status_dict = layer_status_instance.to_dict()
# create an instance of LayerStatus from a dict
layer_status_from_dict = LayerStatus.from_dict(layer_status_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


