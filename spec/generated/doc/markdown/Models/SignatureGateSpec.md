# SignatureGateSpec
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **layers** | [**List**](LayerType.md) | Infrastructure layers to include in signature computation | [default to null] |
| **expectedSignature** | **String** | Expected deterministic composite signature | [default to null] |
| **targetResources** | [**List**](TargetResource.md) | Kubernetes resources this gate controls admission for | [optional] [default to null] |
| **compliancePolicy** | **String** | Name of the CertificationPolicy to enforce | [optional] [default to null] |
| **expectedCertificationHash** | **String** | Expected certification hash from the compliance engine | [optional] [default to null] |
| **verificationIntervalSecs** | **Integer** | How often to re-verify the gate in seconds | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

