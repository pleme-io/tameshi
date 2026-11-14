# GlobalBlastRadiusResponse

Global blast radius report aggregating across all clusters

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**query_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**total_clusters_affected** | **int** | Total clusters containing the compromised artifact | 
**total_nodes_affected** | **int** | Total nodes across all affected clusters | 
**total_pods_affected** | **int** | Total pods across all affected clusters | 
**clusters_not_affected** | **List[str]** | Clusters confirmed NOT affected | 
**cluster_reports** | [**List[ClusterBlastRadius]**](ClusterBlastRadius.md) |  | 
**global_first_seen** | **datetime** | Earliest attestation of this hash across all clusters | [optional] 
**global_last_seen** | **datetime** | Most recent attestation of this hash across all clusters | [optional] 

## Example

```python
from tameshi_client.models.global_blast_radius_response import GlobalBlastRadiusResponse

# TODO update the JSON string below
json = "{}"
# create an instance of GlobalBlastRadiusResponse from a JSON string
global_blast_radius_response_instance = GlobalBlastRadiusResponse.from_json(json)
# print the JSON string representation of the object
print(GlobalBlastRadiusResponse.to_json())

# convert the object into a dict
global_blast_radius_response_dict = global_blast_radius_response_instance.to_dict()
# create an instance of GlobalBlastRadiusResponse from a dict
global_blast_radius_response_from_dict = GlobalBlastRadiusResponse.from_dict(global_blast_radius_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


