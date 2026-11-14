# ClusterBlastRadius

Per-cluster blast radius detail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**cluster_id** | **str** | Cluster identifier | 
**nodes_affected** | **int** | Number of affected nodes in this cluster | 
**pods_affected** | **int** | Number of affected pods in this cluster | 
**first_seen** | **datetime** | First attestation in this cluster | 
**last_seen** | **datetime** | Most recent attestation in this cluster | 
**node_details** | [**List[NodeBlastRadius]**](NodeBlastRadius.md) |  | 

## Example

```python
from tameshi_client.models.cluster_blast_radius import ClusterBlastRadius

# TODO update the JSON string below
json = "{}"
# create an instance of ClusterBlastRadius from a JSON string
cluster_blast_radius_instance = ClusterBlastRadius.from_json(json)
# print the JSON string representation of the object
print(ClusterBlastRadius.to_json())

# convert the object into a dict
cluster_blast_radius_dict = cluster_blast_radius_instance.to_dict()
# create an instance of ClusterBlastRadius from a dict
cluster_blast_radius_from_dict = ClusterBlastRadius.from_dict(cluster_blast_radius_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


