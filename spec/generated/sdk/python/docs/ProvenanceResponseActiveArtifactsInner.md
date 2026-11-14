# ProvenanceResponseActiveArtifactsInner


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**certification_artifact** | [**ProvenanceResponseActiveArtifactsInnerCertificationArtifact**](ProvenanceResponseActiveArtifactsInnerCertificationArtifact.md) |  | 
**signed_root** | [**SignedRoot**](SignedRoot.md) |  | 
**deployment_context** | [**ProvenanceResponseActiveArtifactsInnerDeploymentContext**](ProvenanceResponseActiveArtifactsInnerDeploymentContext.md) |  | 

## Example

```python
from tameshi_client.models.provenance_response_active_artifacts_inner import ProvenanceResponseActiveArtifactsInner

# TODO update the JSON string below
json = "{}"
# create an instance of ProvenanceResponseActiveArtifactsInner from a JSON string
provenance_response_active_artifacts_inner_instance = ProvenanceResponseActiveArtifactsInner.from_json(json)
# print the JSON string representation of the object
print(ProvenanceResponseActiveArtifactsInner.to_json())

# convert the object into a dict
provenance_response_active_artifacts_inner_dict = provenance_response_active_artifacts_inner_instance.to_dict()
# create an instance of ProvenanceResponseActiveArtifactsInner from a dict
provenance_response_active_artifacts_inner_from_dict = ProvenanceResponseActiveArtifactsInner.from_dict(provenance_response_active_artifacts_inner_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


