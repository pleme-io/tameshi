# ApiResponseRunResponse

API response wrapping a compliance run result

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**data** | [**RunResponse**](RunResponse.md) |  | 

## Example

```python
from tameshi_client.models.api_response_run_response import ApiResponseRunResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ApiResponseRunResponse from a JSON string
api_response_run_response_instance = ApiResponseRunResponse.from_json(json)
# print the JSON string representation of the object
print(ApiResponseRunResponse.to_json())

# convert the object into a dict
api_response_run_response_dict = api_response_run_response_instance.to_dict()
# create an instance of ApiResponseRunResponse from a dict
api_response_run_response_from_dict = ApiResponseRunResponse.from_dict(api_response_run_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


