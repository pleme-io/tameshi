# ComputeSignatureRequest

Request to compute a deterministic composite signature

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**layers** | [**List[LayerType]**](LayerType.md) | Infrastructure layers to include in the computation | 
**environment** | **str** | Target environment name | 

## Example

```python
from tameshi_client.models.compute_signature_request import ComputeSignatureRequest

# TODO update the JSON string below
json = "{}"
# create an instance of ComputeSignatureRequest from a JSON string
compute_signature_request_instance = ComputeSignatureRequest.from_json(json)
# print the JSON string representation of the object
print(ComputeSignatureRequest.to_json())

# convert the object into a dict
compute_signature_request_dict = compute_signature_request_instance.to_dict()
# create an instance of ComputeSignatureRequest from a dict
compute_signature_request_from_dict = ComputeSignatureRequest.from_dict(compute_signature_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


