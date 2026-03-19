# LayerSignature

Signature data for a single infrastructure layer

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**layer** | [**LayerType**](LayerType.md) |  | 
**hash** | **str** | BLAKE3 hash of all inputs for this layer | 
**metadata** | [**SignatureMetadata**](SignatureMetadata.md) |  | 
**inputs** | [**List[InputHash]**](InputHash.md) | Individual input hashes that compose this layer signature | 

## Example

```python
from tameshi_client.models.layer_signature import LayerSignature

# TODO update the JSON string below
json = "{}"
# create an instance of LayerSignature from a JSON string
layer_signature_instance = LayerSignature.from_json(json)
# print the JSON string representation of the object
print(LayerSignature.to_json())

# convert the object into a dict
layer_signature_dict = layer_signature_instance.to_dict()
# create an instance of LayerSignature from a dict
layer_signature_from_dict = LayerSignature.from_dict(layer_signature_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


