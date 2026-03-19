# SourceAttestation

Attestation of source code integrity

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**repository** | **str** | Git repository URL | 
**commit** | **str** | Full commit SHA | 
**git_ref** | **str** | Git reference (branch or tag) | 
**commit_signed** | **bool** | Whether the commit has a valid GPG/SSH signature | 
**tree_hash** | **str** | Git tree hash of the commit | 
**flake_lock_hash** | **str** | BLAKE3 hash of flake.lock | 
**flake_input_count** | **int** | Number of flake inputs | 
**all_inputs_pinned** | **bool** | Whether all flake inputs are pinned to exact revisions | 

## Example

```python
from tameshi_client.models.source_attestation import SourceAttestation

# TODO update the JSON string below
json = "{}"
# create an instance of SourceAttestation from a JSON string
source_attestation_instance = SourceAttestation.from_json(json)
# print the JSON string representation of the object
print(SourceAttestation.to_json())

# convert the object into a dict
source_attestation_dict = source_attestation_instance.to_dict()
# create an instance of SourceAttestation from a dict
source_attestation_from_dict = SourceAttestation.from_dict(source_attestation_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


