# GlobalStateRootResponse
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **root\_hash** | **String** | BLAKE3 hash in prefixed hex format | [default to null] |
| **cluster\_roots** | [**Map**](ClusterRootEntry.md) | Per-cluster state, keyed by cluster_id | [default to null] |
| **computed\_at** | **Date** | When this global root was computed | [default to null] |
| **sequence** | **Long** | Monotonically increasing sequence number | [default to null] |
| **previous\_root** | **String** | BLAKE3 hash in prefixed hex format | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

