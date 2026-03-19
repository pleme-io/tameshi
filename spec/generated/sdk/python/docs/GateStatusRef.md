# GateStatusRef

Reference to a gate's status within a certification

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**name** | **str** | Name of the referenced SignatureGate | 
**verified** | **bool** | Whether the gate is currently verified | 
**phase** | [**GatePhase**](GatePhase.md) |  | 
**last_checked_at** | **datetime** | Timestamp of the last status check | [optional] 

## Example

```python
from tameshi_client.models.gate_status_ref import GateStatusRef

# TODO update the JSON string below
json = "{}"
# create an instance of GateStatusRef from a JSON string
gate_status_ref_instance = GateStatusRef.from_json(json)
# print the JSON string representation of the object
print(GateStatusRef.to_json())

# convert the object into a dict
gate_status_ref_dict = gate_status_ref_instance.to_dict()
# create an instance of GateStatusRef from a dict
gate_status_ref_from_dict = GateStatusRef.from_dict(gate_status_ref_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


