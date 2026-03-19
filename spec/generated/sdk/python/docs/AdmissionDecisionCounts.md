# AdmissionDecisionCounts

Running counts of admission decisions made by this gate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**allowed** | **int** | Number of requests allowed through the gate | [optional] 
**denied** | **int** | Number of requests denied by the gate | [optional] 

## Example

```python
from tameshi_client.models.admission_decision_counts import AdmissionDecisionCounts

# TODO update the JSON string below
json = "{}"
# create an instance of AdmissionDecisionCounts from a JSON string
admission_decision_counts_instance = AdmissionDecisionCounts.from_json(json)
# print the JSON string representation of the object
print(AdmissionDecisionCounts.to_json())

# convert the object into a dict
admission_decision_counts_dict = admission_decision_counts_instance.to_dict()
# create an instance of AdmissionDecisionCounts from a dict
admission_decision_counts_from_dict = AdmissionDecisionCounts.from_dict(admission_decision_counts_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


