# ComplianceDistance

Gap analysis between current state and target baseline for a framework

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**target_controls** | **int** | Total number of controls required by the target baseline | 
**satisfied** | **int** | Number of controls currently satisfied | 
**gap** | **int** | Number of unsatisfied controls (targetControls - satisfied) | 
**percentage** | **float** | Compliance percentage (0.0 to 100.0) | 

## Example

```python
from tameshi_client.models.compliance_distance import ComplianceDistance

# TODO update the JSON string below
json = "{}"
# create an instance of ComplianceDistance from a JSON string
compliance_distance_instance = ComplianceDistance.from_json(json)
# print the JSON string representation of the object
print(ComplianceDistance.to_json())

# convert the object into a dict
compliance_distance_dict = compliance_distance_instance.to_dict()
# create an instance of ComplianceDistance from a dict
compliance_distance_from_dict = ComplianceDistance.from_dict(compliance_distance_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


