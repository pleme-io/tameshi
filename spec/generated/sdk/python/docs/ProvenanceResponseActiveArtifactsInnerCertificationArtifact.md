# ProvenanceResponseActiveArtifactsInnerCertificationArtifact

Full CertificationArtifact (3-leaf Merkle binding provenance, compliance, intent)

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**artifact_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**control_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**intent_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**composed_root** | **str** | BLAKE3 hash in prefixed hex format | 

## Example

```python
from tameshi_client.models.provenance_response_active_artifacts_inner_certification_artifact import ProvenanceResponseActiveArtifactsInnerCertificationArtifact

# TODO update the JSON string below
json = "{}"
# create an instance of ProvenanceResponseActiveArtifactsInnerCertificationArtifact from a JSON string
provenance_response_active_artifacts_inner_certification_artifact_instance = ProvenanceResponseActiveArtifactsInnerCertificationArtifact.from_json(json)
# print the JSON string representation of the object
print(ProvenanceResponseActiveArtifactsInnerCertificationArtifact.to_json())

# convert the object into a dict
provenance_response_active_artifacts_inner_certification_artifact_dict = provenance_response_active_artifacts_inner_certification_artifact_instance.to_dict()
# create an instance of ProvenanceResponseActiveArtifactsInnerCertificationArtifact from a dict
provenance_response_active_artifacts_inner_certification_artifact_from_dict = ProvenanceResponseActiveArtifactsInnerCertificationArtifact.from_dict(provenance_response_active_artifacts_inner_certification_artifact_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


