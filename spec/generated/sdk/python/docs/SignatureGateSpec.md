# SignatureGateSpec

Desired state of a SignatureGate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**layers** | [**List[LayerType]**](LayerType.md) | Infrastructure layers to include in signature computation | 
**expected_signature** | **str** | Expected deterministic composite signature | 
**target_resources** | [**List[TargetResource]**](TargetResource.md) | Kubernetes resources this gate controls admission for | [optional] 
**compliance_policy** | **str** | Name of the CertificationPolicy to enforce | [optional] 
**expected_certification_hash** | **str** | Expected certification hash from the compliance engine | [optional] 
**verification_interval_secs** | **int** | How often to re-verify the gate in seconds | [optional] 

## Example

```python
from tameshi_client.models.signature_gate_spec import SignatureGateSpec

# TODO update the JSON string below
json = "{}"
# create an instance of SignatureGateSpec from a JSON string
signature_gate_spec_instance = SignatureGateSpec.from_json(json)
# print the JSON string representation of the object
print(SignatureGateSpec.to_json())

# convert the object into a dict
signature_gate_spec_dict = signature_gate_spec_instance.to_dict()
# create an instance of SignatureGateSpec from a dict
signature_gate_spec_from_dict = SignatureGateSpec.from_dict(signature_gate_spec_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


