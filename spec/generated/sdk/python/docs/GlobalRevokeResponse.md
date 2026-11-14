# GlobalRevokeResponse

Aggregate result of revoking a hash across all clusters

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**total_clusters_revoked** | **int** | Number of clusters where revocation was applied | 
**total_nodes_affected** | **int** | Total nodes across all clusters where hash was revoked | 
**total_bpf_maps_updated** | **int** | Total BPF maps updated across all clusters | 
**cluster_results** | [**List[RevokeResponse]**](RevokeResponse.md) | Per-cluster revocation results | 

## Example

```python
from tameshi_client.models.global_revoke_response import GlobalRevokeResponse

# TODO update the JSON string below
json = "{}"
# create an instance of GlobalRevokeResponse from a JSON string
global_revoke_response_instance = GlobalRevokeResponse.from_json(json)
# print the JSON string representation of the object
print(GlobalRevokeResponse.to_json())

# convert the object into a dict
global_revoke_response_dict = global_revoke_response_instance.to_dict()
# create an instance of GlobalRevokeResponse from a dict
global_revoke_response_from_dict = GlobalRevokeResponse.from_dict(global_revoke_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


