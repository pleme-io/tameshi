# ApiResponseHashResponse

API response wrapping a compliance hash

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**data** | [**HashResponse**](HashResponse.md) |  | 

## Example

```python
from tameshi_client.models.api_response_hash_response import ApiResponseHashResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ApiResponseHashResponse from a JSON string
api_response_hash_response_instance = ApiResponseHashResponse.from_json(json)
# print the JSON string representation of the object
print(ApiResponseHashResponse.to_json())

# convert the object into a dict
api_response_hash_response_dict = api_response_hash_response_instance.to_dict()
# create an instance of ApiResponseHashResponse from a dict
api_response_hash_response_from_dict = ApiResponseHashResponse.from_dict(api_response_hash_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


