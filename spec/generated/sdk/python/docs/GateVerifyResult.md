# GateVerifyResult

Result of an on-demand gate verification

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**name** | **str** | Name of the verified gate | 
**verified** | **bool** | Whether the gate passed verification | 
**phase** | [**GatePhase**](GatePhase.md) |  | 
**expected_signature** | **str** | The expected composite signature | [optional] 
**current_signature** | **str** | The freshly computed composite signature | [optional] 
**layer_statuses** | [**List[LayerStatus]**](LayerStatus.md) | Per-layer verification results | [optional] 

## Example

```python
from tameshi_client.models.gate_verify_result import GateVerifyResult

# TODO update the JSON string below
json = "{}"
# create an instance of GateVerifyResult from a JSON string
gate_verify_result_instance = GateVerifyResult.from_json(json)
# print the JSON string representation of the object
print(GateVerifyResult.to_json())

# convert the object into a dict
gate_verify_result_dict = gate_verify_result_instance.to_dict()
# create an instance of GateVerifyResult from a dict
gate_verify_result_from_dict = GateVerifyResult.from_dict(gate_verify_result_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


