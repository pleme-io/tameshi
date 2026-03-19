# SignatureGateStatus

Observed state of a SignatureGate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**phase** | [**GatePhase**](GatePhase.md) |  | 
**current_signature** | **str** | Most recently computed composite signature | [optional] 
**last_verified_at** | **datetime** | Timestamp of the last successful verification | [optional] 
**layer_statuses** | [**List[LayerStatus]**](LayerStatus.md) | Per-layer verification status | [optional] 
**message** | **str** | Human-readable status message | [optional] 
**failure_count** | **int** | Number of consecutive verification failures | [optional] 
**admission_decisions** | [**AdmissionDecisionCounts**](AdmissionDecisionCounts.md) |  | [optional] 

## Example

```python
from tameshi_client.models.signature_gate_status import SignatureGateStatus

# TODO update the JSON string below
json = "{}"
# create an instance of SignatureGateStatus from a JSON string
signature_gate_status_instance = SignatureGateStatus.from_json(json)
# print the JSON string representation of the object
print(SignatureGateStatus.to_json())

# convert the object into a dict
signature_gate_status_dict = signature_gate_status_instance.to_dict()
# create an instance of SignatureGateStatus from a dict
signature_gate_status_from_dict = SignatureGateStatus.from_dict(signature_gate_status_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


