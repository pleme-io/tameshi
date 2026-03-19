# GateDecision

An admission decision made by a signature gate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**allowed** | **bool** | Whether the admission request was allowed | 
**reason** | **str** | Human-readable reason for the decision | 
**signature** | **str** | Current gate signature at time of decision | 
**expected** | **str** | Expected gate signature at time of decision | 
**decided_at** | **datetime** | Timestamp of the admission decision | 
**gate** | **str** | Name of the gate that made the decision | 

## Example

```python
from tameshi_client.models.gate_decision import GateDecision

# TODO update the JSON string below
json = "{}"
# create an instance of GateDecision from a JSON string
gate_decision_instance = GateDecision.from_json(json)
# print the JSON string representation of the object
print(GateDecision.to_json())

# convert the object into a dict
gate_decision_dict = gate_decision_instance.to_dict()
# create an instance of GateDecision from a dict
gate_decision_from_dict = GateDecision.from_dict(gate_decision_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


