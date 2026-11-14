# ClusterRootEntry

A single cluster's contribution to the global state root

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**cluster_id** | **str** | Unique cluster identifier (e.g. plo-us-east, edge-fleet-07) | 
**cluster_root** | **str** | BLAKE3 hash in prefixed hex format | 
**signed_root** | [**SignedRoot**](SignedRoot.md) |  | 
**node_count** | **int** | Number of nodes reporting attestations | 
**artifact_count** | **int** | Total number of CertificationArtifacts across all nodes | 
**last_reported** | **datetime** | Last time this cluster reported its root | 
**status** | [**ClusterStatus**](ClusterStatus.md) |  | 

## Example

```python
from tameshi_client.models.cluster_root_entry import ClusterRootEntry

# TODO update the JSON string below
json = "{}"
# create an instance of ClusterRootEntry from a JSON string
cluster_root_entry_instance = ClusterRootEntry.from_json(json)
# print the JSON string representation of the object
print(ClusterRootEntry.to_json())

# convert the object into a dict
cluster_root_entry_dict = cluster_root_entry_instance.to_dict()
# create an instance of ClusterRootEntry from a dict
cluster_root_entry_from_dict = ClusterRootEntry.from_dict(cluster_root_entry_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


