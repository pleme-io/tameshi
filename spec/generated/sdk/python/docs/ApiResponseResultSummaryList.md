# ApiResponseResultSummaryList

API response wrapping a list of compliance result summaries

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**data** | [**List[ResultSummary]**](ResultSummary.md) | List of compliance result summaries | 

## Example

```python
from tameshi_client.models.api_response_result_summary_list import ApiResponseResultSummaryList

# TODO update the JSON string below
json = "{}"
# create an instance of ApiResponseResultSummaryList from a JSON string
api_response_result_summary_list_instance = ApiResponseResultSummaryList.from_json(json)
# print the JSON string representation of the object
print(ApiResponseResultSummaryList.to_json())

# convert the object into a dict
api_response_result_summary_list_dict = api_response_result_summary_list_instance.to_dict()
# create an instance of ApiResponseResultSummaryList from a dict
api_response_result_summary_list_from_dict = ApiResponseResultSummaryList.from_dict(api_response_result_summary_list_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


