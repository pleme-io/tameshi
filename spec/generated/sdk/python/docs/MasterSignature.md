# MasterSignature

Composite master signature across all infrastructure layers

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**untested** | **str** | Raw composite hash before compliance or security attestation | 
**compliance** | **str** | Hash incorporating compliance assessment results | [optional] 
**secure** | **str** | Hash incorporating security scan results | [optional] 
**layers** | [**List[LayerSignature]**](LayerSignature.md) | Per-layer signatures that compose the master | 
**computed_at** | **datetime** | Timestamp when the master signature was computed | 
**environment** | **str** | Environment the master signature covers | 

## Example

```python
from tameshi_client.models.master_signature import MasterSignature

# TODO update the JSON string below
json = "{}"
# create an instance of MasterSignature from a JSON string
master_signature_instance = MasterSignature.from_json(json)
# print the JSON string representation of the object
print(MasterSignature.to_json())

# convert the object into a dict
master_signature_dict = master_signature_instance.to_dict()
# create an instance of MasterSignature from a dict
master_signature_from_dict = MasterSignature.from_dict(master_signature_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


