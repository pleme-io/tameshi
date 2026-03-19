# AkeylessSecretAttestation

Attestation of Akeyless secret access during deployment

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**gateway_url** | **str** | URL of the Akeyless Gateway | 
**auth_method** | [**AkeylessAuthMethod**](AkeylessAuthMethod.md) |  | 
**secrets_accessed** | [**List[AkeylessSecretAccess]**](AkeylessSecretAccess.md) | List of secrets accessed during deployment | 
**gateway_certificate_hash** | **str** | BLAKE3 hash of the gateway TLS certificate | 
**session_hash** | **str** | BLAKE3 hash of the authentication session | 

## Example

```python
from tameshi_client.models.akeyless_secret_attestation import AkeylessSecretAttestation

# TODO update the JSON string below
json = "{}"
# create an instance of AkeylessSecretAttestation from a JSON string
akeyless_secret_attestation_instance = AkeylessSecretAttestation.from_json(json)
# print the JSON string representation of the object
print(AkeylessSecretAttestation.to_json())

# convert the object into a dict
akeyless_secret_attestation_dict = akeyless_secret_attestation_instance.to_dict()
# create an instance of AkeylessSecretAttestation from a dict
akeyless_secret_attestation_from_dict = AkeylessSecretAttestation.from_dict(akeyless_secret_attestation_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


