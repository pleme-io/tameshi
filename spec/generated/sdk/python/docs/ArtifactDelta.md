# ArtifactDelta

Delta of artifacts since last report (bandwidth optimization)

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**added** | [**List[ArtifactLocation]**](ArtifactLocation.md) | Artifacts added since last report | 
**removed** | **List[str]** | Composed root hashes of artifacts removed since last report | 

## Example

```python
from tameshi_client.models.artifact_delta import ArtifactDelta

# TODO update the JSON string below
json = "{}"
# create an instance of ArtifactDelta from a JSON string
artifact_delta_instance = ArtifactDelta.from_json(json)
# print the JSON string representation of the object
print(ArtifactDelta.to_json())

# convert the object into a dict
artifact_delta_dict = artifact_delta_instance.to_dict()
# create an instance of ArtifactDelta from a dict
artifact_delta_from_dict = ArtifactDelta.from_dict(artifact_delta_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


