# CoResidentArtifact

An artifact that shared the same Merkle root as the compromised hash

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**composed_root** | **str** | BLAKE3 hash in prefixed hex format | 
**artifact_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**control_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**intent_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**binary_path** | **str** | Nix store path or binary path of the co-resident artifact | 

## Example

```python
from tameshi_client.models.co_resident_artifact import CoResidentArtifact

# TODO update the JSON string below
json = "{}"
# create an instance of CoResidentArtifact from a JSON string
co_resident_artifact_instance = CoResidentArtifact.from_json(json)
# print the JSON string representation of the object
print(CoResidentArtifact.to_json())

# convert the object into a dict
co_resident_artifact_dict = co_resident_artifact_instance.to_dict()
# create an instance of CoResidentArtifact from a dict
co_resident_artifact_from_dict = CoResidentArtifact.from_dict(co_resident_artifact_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


