# SignedRoot

A signed Merkle root with signature metadata

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**root** | **str** | BLAKE3 hash in prefixed hex format | 
**signature** | **str** | Base64-encoded cryptographic signature | 
**algorithm** | [**SigningAlgorithm**](SigningAlgorithm.md) |  | 
**signer_id** | **str** | Identity of the signer (key fingerprint or secrets-manager key path) | 
**signed_at** | **datetime** | Timestamp when the root was signed | 

## Example

```python
from tameshi_client.models.signed_root import SignedRoot

# TODO update the JSON string below
json = "{}"
# create an instance of SignedRoot from a JSON string
signed_root_instance = SignedRoot.from_json(json)
# print the JSON string representation of the object
print(SignedRoot.to_json())

# convert the object into a dict
signed_root_dict = signed_root_instance.to_dict()
# create an instance of SignedRoot from a dict
signed_root_from_dict = SignedRoot.from_dict(signed_root_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


