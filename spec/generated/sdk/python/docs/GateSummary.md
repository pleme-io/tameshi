# GateSummary

Abbreviated view of a SignatureGate for list responses

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**name** | **str** | Name of the SignatureGate resource | 
**namespace** | **str** | Kubernetes namespace | 
**phase** | [**GatePhase**](GatePhase.md) |  | 
**layers** | [**List[LayerType]**](LayerType.md) | Infrastructure layers this gate covers | 
**expected_signature** | **str** | Expected composite signature | [optional] 
**current_signature** | **str** | Most recently computed composite signature | [optional] 

## Example

```python
from tameshi_client.models.gate_summary import GateSummary

# TODO update the JSON string below
json = "{}"
# create an instance of GateSummary from a JSON string
gate_summary_instance = GateSummary.from_json(json)
# print the JSON string representation of the object
print(GateSummary.to_json())

# convert the object into a dict
gate_summary_dict = gate_summary_instance.to_dict()
# create an instance of GateSummary from a dict
gate_summary_from_dict = GateSummary.from_dict(gate_summary_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


