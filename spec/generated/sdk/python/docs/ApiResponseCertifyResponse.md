# ApiResponseCertifyResponse

API response wrapping a certification result

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**data** | [**CertifyResponse**](CertifyResponse.md) |  | 

## Example

```python
from tameshi_client.models.api_response_certify_response import ApiResponseCertifyResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ApiResponseCertifyResponse from a JSON string
api_response_certify_response_instance = ApiResponseCertifyResponse.from_json(json)
# print the JSON string representation of the object
print(ApiResponseCertifyResponse.to_json())

# convert the object into a dict
api_response_certify_response_dict = api_response_certify_response_instance.to_dict()
# create an instance of ApiResponseCertifyResponse from a dict
api_response_certify_response_from_dict = ApiResponseCertifyResponse.from_dict(api_response_certify_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


