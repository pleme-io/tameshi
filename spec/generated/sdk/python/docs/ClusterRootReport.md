# ClusterRootReport

Report sent by a local cluster to the master server

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**cluster_id** | **str** | Unique cluster identifier | 
**cluster_root** | **str** | BLAKE3 hash in prefixed hex format | 
**signed_root** | [**SignedRoot**](SignedRoot.md) |  | 
**node_count** | **int** | Number of nodes reporting attestations | 
**artifact_count** | **int** | Total number of CertificationArtifacts across all nodes | 
**reported_at** | **datetime** | When this report was generated | 
**artifact_delta** | [**ArtifactDelta**](ArtifactDelta.md) |  | [optional] 

## Example

```python
from tameshi_client.models.cluster_root_report import ClusterRootReport

# TODO update the JSON string below
json = "{}"
# create an instance of ClusterRootReport from a JSON string
cluster_root_report_instance = ClusterRootReport.from_json(json)
# print the JSON string representation of the object
print(ClusterRootReport.to_json())

# convert the object into a dict
cluster_root_report_dict = cluster_root_report_instance.to_dict()
# create an instance of ClusterRootReport from a dict
cluster_root_report_from_dict = ClusterRootReport.from_dict(cluster_root_report_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


