# VerifierIdentity

Identity of the component that produced a heartbeat entry

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**component** | **str** | Component name (e.g. sekiban, kensa, inshou) | 
**instance** | **str** | Instance identifier (e.g. pod name, hostname) | 
**version** | **str** | Component version | 

## Example

```python
from tameshi_client.models.verifier_identity import VerifierIdentity

# TODO update the JSON string below
json = "{}"
# create an instance of VerifierIdentity from a JSON string
verifier_identity_instance = VerifierIdentity.from_json(json)
# print the JSON string representation of the object
print(VerifierIdentity.to_json())

# convert the object into a dict
verifier_identity_dict = verifier_identity_instance.to_dict()
# create an instance of VerifierIdentity from a dict
verifier_identity_from_dict = VerifierIdentity.from_dict(verifier_identity_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


