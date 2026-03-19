# LayerVerification

Verification result for a single layer

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**layer** | [**LayerType**](LayerType.md) |  | 
**passed** | **bool** | Whether this layer passed verification | 
**expected** | **str** | Expected hash for this layer | 
**actual** | **str** | Actual computed hash for this layer | 

## Example

```python
from tameshi_client.models.layer_verification import LayerVerification

# TODO update the JSON string below
json = "{}"
# create an instance of LayerVerification from a JSON string
layer_verification_instance = LayerVerification.from_json(json)
# print the JSON string representation of the object
print(LayerVerification.to_json())

# convert the object into a dict
layer_verification_dict = layer_verification_instance.to_dict()
# create an instance of LayerVerification from a dict
layer_verification_from_dict = LayerVerification.from_dict(layer_verification_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


