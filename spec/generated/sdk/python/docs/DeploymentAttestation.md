# DeploymentAttestation

Attestation of a Kubernetes deployment

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**namespace** | **str** | Kubernetes namespace | 
**kustomization** | **str** | FluxCD Kustomization name | 
**source_commit** | **str** | Git commit the deployment was sourced from | 
**source_verified** | **bool** | Whether the source commit signature was verified | 
**manifest_hash** | **str** | BLAKE3 hash of rendered Kubernetes manifests | 
**all_releases_signed** | **bool** | Whether all HelmRelease resources have verified signatures | 
**cis_k8s_pass_rate** | **float** | CIS Kubernetes benchmark pass rate (0.0 to 1.0) | [optional] 
**network_policies_verified** | **bool** | Whether required NetworkPolicy resources are in place | 
**running_pods** | **int** | Number of running pods in the deployment | 
**all_healthy** | **bool** | Whether all pods are in healthy state | 

## Example

```python
from tameshi_client.models.deployment_attestation import DeploymentAttestation

# TODO update the JSON string below
json = "{}"
# create an instance of DeploymentAttestation from a JSON string
deployment_attestation_instance = DeploymentAttestation.from_json(json)
# print the JSON string representation of the object
print(DeploymentAttestation.to_json())

# convert the object into a dict
deployment_attestation_dict = deployment_attestation_instance.to_dict()
# create an instance of DeploymentAttestation from a dict
deployment_attestation_from_dict = DeploymentAttestation.from_dict(deployment_attestation_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


