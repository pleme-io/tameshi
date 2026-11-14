# ConsistencyProof
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **fromSeq** | **Long** | Sequence number of the earlier chain state | [default to null] |
| **toSeq** | **Long** | Sequence number of the later chain state | [default to null] |
| **fromHash** | **String** | BLAKE3 hash in prefixed hex format | [default to null] |
| **toHash** | **String** | BLAKE3 hash in prefixed hex format | [default to null] |
| **proofNodes** | **List** | BLAKE3 intermediate hashes forming the consistency proof | [default to null] |
| **verified** | **Boolean** | Whether the proof has been verified server-side | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

