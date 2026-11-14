# ArtifactLocation

Location of an artifact in the global fleet

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**cluster_id** | **str** | Cluster where the artifact resides | 
**node** | **str** | Node within the cluster | 
**namespace** | **str** | Kubernetes namespace | 
**pod** | **str** | Pod name | 
**binary_path** | **str** | Path to the binary on disk | 
**composed_root** | **str** | BLAKE3 hash in prefixed hex format | 

## Example

```python
from tameshi_client.models.artifact_location import ArtifactLocation

# TODO update the JSON string below
json = "{}"
# create an instance of ArtifactLocation from a JSON string
artifact_location_instance = ArtifactLocation.from_json(json)
# print the JSON string representation of the object
print(ArtifactLocation.to_json())

# convert the object into a dict
artifact_location_dict = artifact_location_instance.to_dict()
# create an instance of ArtifactLocation from a dict
artifact_location_from_dict = ArtifactLocation.from_dict(artifact_location_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


