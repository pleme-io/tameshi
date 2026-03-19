# ComputeSignatureResponse

Result of a signature computation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**signature** | **str** | Computed BLAKE3 composite signature | 
**layers** | **List[str]** | Layer types that contributed to the signature | 
**environment** | **str** | Environment the signature was computed for | 

## Example

```python
from tameshi_client.models.compute_signature_response import ComputeSignatureResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ComputeSignatureResponse from a JSON string
compute_signature_response_instance = ComputeSignatureResponse.from_json(json)
# print the JSON string representation of the object
print(ComputeSignatureResponse.to_json())

# convert the object into a dict
compute_signature_response_dict = compute_signature_response_instance.to_dict()
# create an instance of ComputeSignatureResponse from a dict
compute_signature_response_from_dict = ComputeSignatureResponse.from_dict(compute_signature_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


