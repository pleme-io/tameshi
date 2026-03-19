# ComplianceResult

Full compliance assessment result

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **str** | Unique identifier for this compliance result | 
**environment** | **str** | Environment that was assessed | 
**baseline** | [**ComplianceBaseline**](ComplianceBaseline.md) |  | 
**framework_hash** | **str** | BLAKE3 hash of the compliance framework definition | 
**catalog_hash** | **str** | BLAKE3 hash of the control catalog | 
**assessment_result** | **object** | Full OSCAL assessment result object | 
**compliance_hash** | **str** | BLAKE3 hash of the entire assessment result | 
**all_satisfied** | **bool** | Whether all controls are satisfied | 
**computed_at** | **datetime** | When the result was computed | 

## Example

```python
from tameshi_client.models.compliance_result import ComplianceResult

# TODO update the JSON string below
json = "{}"
# create an instance of ComplianceResult from a JSON string
compliance_result_instance = ComplianceResult.from_json(json)
# print the JSON string representation of the object
print(ComplianceResult.to_json())

# convert the object into a dict
compliance_result_dict = compliance_result_instance.to_dict()
# create an instance of ComplianceResult from a dict
compliance_result_from_dict = ComplianceResult.from_dict(compliance_result_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


