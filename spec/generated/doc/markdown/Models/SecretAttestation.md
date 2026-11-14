# SecretAttestation
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **gatewayUrl** | **String** | URL of the secrets-manager Gateway | [default to null] |
| **authMethod** | [**SecretAuthMethod**](SecretAuthMethod.md) |  | [default to null] |
| **secretsAccessed** | [**List**](SecretAccess.md) | List of secrets accessed during deployment | [default to null] |
| **gatewayCertificateHash** | **String** | BLAKE3 hash of the gateway TLS certificate | [default to null] |
| **sessionHash** | **String** | BLAKE3 hash of the authentication session | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

