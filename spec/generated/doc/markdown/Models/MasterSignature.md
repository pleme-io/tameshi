# MasterSignature
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **untested** | **String** | Raw composite hash before compliance or security attestation | [default to null] |
| **compliance** | **String** | Hash incorporating compliance assessment results | [optional] [default to null] |
| **secure** | **String** | Hash incorporating security scan results | [optional] [default to null] |
| **layers** | [**List**](LayerSignature.md) | Per-layer signatures that compose the master | [default to null] |
| **computedAt** | **Date** | Timestamp when the master signature was computed | [default to null] |
| **environment** | **String** | Environment the master signature covers | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

