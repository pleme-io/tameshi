# SecretAttestation

Attestation of secrets-manager secret access during deployment

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**gateway_url** | **str** | URL of the secrets-manager Gateway | 
**auth_method** | [**SecretAuthMethod**](SecretAuthMethod.md) |  | 
**secrets_accessed** | [**List[SecretAccess]**](SecretAccess.md) | List of secrets accessed during deployment | 
**gateway_certificate_hash** | **str** | BLAKE3 hash of the gateway TLS certificate | 
**session_hash** | **str** | BLAKE3 hash of the authentication session | 

## Example

```python
from tameshi_client.models.secret_attestation import SecretAttestation

# TODO update the JSON string below
json = "{}"
# create an instance of SecretAttestation from a JSON string
secret_attestation_instance = SecretAttestation.from_json(json)
# print the JSON string representation of the object
print(SecretAttestation.to_json())

# convert the object into a dict
secret_attestation_dict = secret_attestation_instance.to_dict()
# create an instance of SecretAttestation from a dict
secret_attestation_from_dict = SecretAttestation.from_dict(secret_attestation_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


