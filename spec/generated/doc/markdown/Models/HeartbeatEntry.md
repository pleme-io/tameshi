# HeartbeatEntry
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **sequence** | **Long** | Monotonically increasing sequence number | [default to null] |
| **timestamp** | **Date** | When the heartbeat event occurred | [default to null] |
| **verifier** | [**VerifierIdentity**](VerifierIdentity.md) |  | [default to null] |
| **event** | [**HeartbeatEvent**](HeartbeatEvent.md) |  | [default to null] |
| **result** | [**VerificationOutcome**](VerificationOutcome.md) |  | [default to null] |
| **resource** | **String** | Identifier of the resource involved (e.g. apps/v1/Deployment/my-app) | [default to null] |
| **signatureChecked** | **String** | BLAKE3 signature hash that was checked during this event | [default to null] |
| **entryHash** | **String** | BLAKE3 hash in prefixed hex format | [default to null] |
| **previousHash** | **String** | BLAKE3 hash in prefixed hex format | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

