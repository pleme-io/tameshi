# ProvenanceResponse

Point-in-time snapshot of all active artifacts on a node

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**node** | **str** | Node name queried | 
**timestamp** | **datetime** | Point-in-time that was queried | 
**active_artifacts** | [**List[ProvenanceResponseActiveArtifactsInner]**](ProvenanceResponseActiveArtifactsInner.md) | All CertificationArtifacts active on the node at the queried time | 

## Example

```python
from tameshi_client.models.provenance_response import ProvenanceResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ProvenanceResponse from a JSON string
provenance_response_instance = ProvenanceResponse.from_json(json)
# print the JSON string representation of the object
print(ProvenanceResponse.to_json())

# convert the object into a dict
provenance_response_dict = provenance_response_instance.to_dict()
# create an instance of ProvenanceResponse from a dict
provenance_response_from_dict = ProvenanceResponse.from_dict(provenance_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


