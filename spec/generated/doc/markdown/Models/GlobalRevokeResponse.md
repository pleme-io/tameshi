# GlobalRevokeResponse
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **total\_clusters\_revoked** | **Integer** | Number of clusters where revocation was applied | [default to null] |
| **total\_nodes\_affected** | **Integer** | Total nodes across all clusters where hash was revoked | [default to null] |
| **total\_bpf\_maps\_updated** | **Integer** | Total BPF maps updated across all clusters | [default to null] |
| **cluster\_results** | [**List**](RevokeResponse.md) | Per-cluster revocation results | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

