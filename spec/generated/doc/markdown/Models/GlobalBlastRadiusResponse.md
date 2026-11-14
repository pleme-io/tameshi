# GlobalBlastRadiusResponse
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **query\_hash** | **String** | BLAKE3 hash in prefixed hex format | [default to null] |
| **total\_clusters\_affected** | **Integer** | Total clusters containing the compromised artifact | [default to null] |
| **total\_nodes\_affected** | **Integer** | Total nodes across all affected clusters | [default to null] |
| **total\_pods\_affected** | **Integer** | Total pods across all affected clusters | [default to null] |
| **clusters\_not\_affected** | **List** | Clusters confirmed NOT affected | [default to null] |
| **cluster\_reports** | [**List**](ClusterBlastRadius.md) |  | [default to null] |
| **global\_first\_seen** | **Date** | Earliest attestation of this hash across all clusters | [optional] [default to null] |
| **global\_last\_seen** | **Date** | Most recent attestation of this hash across all clusters | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

