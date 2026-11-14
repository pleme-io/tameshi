# VerifySignedRoot200Response


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**verified** | **bool** | Whether the signed root is valid | 

## Example

```python
from tameshi_client.models.verify_signed_root200_response import VerifySignedRoot200Response

# TODO update the JSON string below
json = "{}"
# create an instance of VerifySignedRoot200Response from a JSON string
verify_signed_root200_response_instance = VerifySignedRoot200Response.from_json(json)
# print the JSON string representation of the object
print(VerifySignedRoot200Response.to_json())

# convert the object into a dict
verify_signed_root200_response_dict = verify_signed_root200_response_instance.to_dict()
# create an instance of VerifySignedRoot200Response from a dict
verify_signed_root200_response_from_dict = VerifySignedRoot200Response.from_dict(verify_signed_root200_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


