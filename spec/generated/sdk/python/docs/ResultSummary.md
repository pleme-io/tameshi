# ResultSummary

Abbreviated view of a compliance result

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **str** | Unique identifier for this compliance result | 
**environment** | **str** | Environment that was assessed | 
**baseline** | [**ComplianceBaseline**](ComplianceBaseline.md) |  | 
**compliance_hash** | **str** | BLAKE3 hash of the assessment result | 
**all_satisfied** | **bool** | Whether all controls are satisfied | 
**total_controls** | **int** | Total number of controls assessed | 
**satisfied** | **int** | Number of satisfied controls | 
**not_satisfied** | **int** | Number of unsatisfied controls | 
**performed_at** | **datetime** | When the assessment was performed | 

## Example

```python
from tameshi_client.models.result_summary import ResultSummary

# TODO update the JSON string below
json = "{}"
# create an instance of ResultSummary from a JSON string
result_summary_instance = ResultSummary.from_json(json)
# print the JSON string representation of the object
print(ResultSummary.to_json())

# convert the object into a dict
result_summary_dict = result_summary_instance.to_dict()
# create an instance of ResultSummary from a dict
result_summary_from_dict = ResultSummary.from_dict(result_summary_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


