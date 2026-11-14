# RevokeResponse
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **revoked** | **Boolean** | Whether the revocation was successfully applied | [default to null] |
| **affected\_nodes** | **Integer** | Number of nodes where the hash was revoked | [default to null] |
| **bpf\_maps\_updated** | **Boolean** | Whether kanshi BPF allow-maps were updated on all affected nodes | [default to null] |
| **heartbeat\_entry\_sequence** | **Long** | Sequence number of the Revocation event in the HeartbeatChain | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

