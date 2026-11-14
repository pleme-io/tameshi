# ClusterRootEntry
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **cluster\_id** | **String** | Unique cluster identifier (e.g. plo-us-east, edge-fleet-07) | [default to null] |
| **cluster\_root** | **String** | BLAKE3 hash in prefixed hex format | [default to null] |
| **signed\_root** | [**SignedRoot**](SignedRoot.md) |  | [default to null] |
| **node\_count** | **Integer** | Number of nodes reporting attestations | [default to null] |
| **artifact\_count** | **Long** | Total number of CertificationArtifacts across all nodes | [default to null] |
| **last\_reported** | **Date** | Last time this cluster reported its root | [default to null] |
| **status** | [**ClusterStatus**](ClusterStatus.md) |  | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

