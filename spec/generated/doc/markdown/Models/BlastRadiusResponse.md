# BlastRadiusResponse
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **query\_hash** | **String** | BLAKE3 hash in prefixed hex format | [default to null] |
| **total\_affected** | **Integer** | Total number of affected nodes | [default to null] |
| **time\_range** | [**BlastRadiusResponse_time_range**](BlastRadiusResponse_time_range.md) |  | [default to null] |
| **affected\_nodes** | [**List**](AffectedNode.md) | List of nodes where the compromised hash was active | [default to null] |
| **co\_resident\_artifacts** | [**List**](CoResidentArtifact.md) | Other artifacts that shared the same Merkle root as the compromised hash | [default to null] |
| **merkle\_proof** | [**BlastRadiusResponse_merkle_proof**](BlastRadiusResponse_merkle_proof.md) |  | [optional] [default to null] |
| **chain\_integrity** | **Boolean** | Whether the ledger hash chain is intact for the queried range | [default to null] |
| **evidence\_hash** | **String** | BLAKE3 hash in prefixed hex format | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

