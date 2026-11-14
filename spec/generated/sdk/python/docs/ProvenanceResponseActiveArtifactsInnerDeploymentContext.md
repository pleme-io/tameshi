# ProvenanceResponseActiveArtifactsInnerDeploymentContext

Deployment context at the queried timestamp

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**cluster** | **str** | Kubernetes cluster name | 
**namespace** | **str** | Kubernetes namespace | 
**node** | **str** | Node name | 
**pod** | **str** | Pod name | 
**container** | **str** | Container name | 
**image_ref** | **str** | Full container image reference | 
**binary_paths** | **List[str]** | Nix store paths or binary paths within the container | 
**sdlc_chain_hash** | **str** | BLAKE3 hash in prefixed hex format | [optional] 
**compliance_report_hash** | **str** | BLAKE3 hash in prefixed hex format | [optional] 

## Example

```python
from tameshi_client.models.provenance_response_active_artifacts_inner_deployment_context import ProvenanceResponseActiveArtifactsInnerDeploymentContext

# TODO update the JSON string below
json = "{}"
# create an instance of ProvenanceResponseActiveArtifactsInnerDeploymentContext from a JSON string
provenance_response_active_artifacts_inner_deployment_context_instance = ProvenanceResponseActiveArtifactsInnerDeploymentContext.from_json(json)
# print the JSON string representation of the object
print(ProvenanceResponseActiveArtifactsInnerDeploymentContext.to_json())

# convert the object into a dict
provenance_response_active_artifacts_inner_deployment_context_dict = provenance_response_active_artifacts_inner_deployment_context_instance.to_dict()
# create an instance of ProvenanceResponseActiveArtifactsInnerDeploymentContext from a dict
provenance_response_active_artifacts_inner_deployment_context_from_dict = ProvenanceResponseActiveArtifactsInnerDeploymentContext.from_dict(provenance_response_active_artifacts_inner_deployment_context_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


