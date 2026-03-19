# SignatureGate

Full SignatureGate resource with spec and status

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**name** | **str** | Name of the SignatureGate resource | 
**namespace** | **str** | Kubernetes namespace | 
**spec** | [**SignatureGateSpec**](SignatureGateSpec.md) |  | 
**status** | [**SignatureGateStatus**](SignatureGateStatus.md) |  | 

## Example

```python
from tameshi_client.models.signature_gate import SignatureGate

# TODO update the JSON string below
json = "{}"
# create an instance of SignatureGate from a JSON string
signature_gate_instance = SignatureGate.from_json(json)
# print the JSON string representation of the object
print(SignatureGate.to_json())

# convert the object into a dict
signature_gate_dict = signature_gate_instance.to_dict()
# create an instance of SignatureGate from a dict
signature_gate_from_dict = SignatureGate.from_dict(signature_gate_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


