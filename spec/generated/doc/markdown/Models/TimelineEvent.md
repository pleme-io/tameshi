# TimelineEvent
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **timestamp** | **Date** | When the verification event occurred | [default to null] |
| **event\_type** | [**HeartbeatEvent**](HeartbeatEvent.md) |  | [default to null] |
| **decision** | [**VerificationOutcome**](VerificationOutcome.md) |  | [default to null] |
| **node** | **String** | Node where the event occurred | [default to null] |
| **pod** | **String** | Pod that triggered the event | [default to null] |
| **binary\_path** | **String** | Path of the binary being verified | [default to null] |
| **composed\_root** | **String** | BLAKE3 hash in prefixed hex format | [default to null] |
| **sequence** | **Long** | Ledger sequence number for this event | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

