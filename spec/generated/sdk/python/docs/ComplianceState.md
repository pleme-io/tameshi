# ComplianceState

Aggregate compliance state across all active frameworks

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**status** | **str** | Overall compliance status | 
**distance** | **float** | Aggregate distance from full compliance (0.0 &#x3D; fully compliant, 1.0 &#x3D; fully non-compliant) | 
**frameworks** | **List[str]** | Active compliance frameworks being assessed | 
**last_assessed_at** | **datetime** | Timestamp of the most recent compliance assessment | 
**hash** | **str** | BLAKE3 hash in prefixed hex format | 

## Example

```python
from tameshi_client.models.compliance_state import ComplianceState

# TODO update the JSON string below
json = "{}"
# create an instance of ComplianceState from a JSON string
compliance_state_instance = ComplianceState.from_json(json)
# print the JSON string representation of the object
print(ComplianceState.to_json())

# convert the object into a dict
compliance_state_dict = compliance_state_instance.to_dict()
# create an instance of ComplianceState from a dict
compliance_state_from_dict = ComplianceState.from_dict(compliance_state_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


