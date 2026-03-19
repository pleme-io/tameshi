# AkeylessSecretAccess

Record of a single Akeyless secret access

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**path** | **str** | Akeyless secret path | 
**secret_type** | [**AkeylessSecretType**](AkeylessSecretType.md) |  | 
**value_hash** | **str** | BLAKE3 hash of the secret value (not the secret itself) | 
**accessed_at** | **datetime** | Timestamp when the secret was accessed | 
**version** | **int** | Secret version number | [optional] 

## Example

```python
from tameshi_client.models.akeyless_secret_access import AkeylessSecretAccess

# TODO update the JSON string below
json = "{}"
# create an instance of AkeylessSecretAccess from a JSON string
akeyless_secret_access_instance = AkeylessSecretAccess.from_json(json)
# print the JSON string representation of the object
print(AkeylessSecretAccess.to_json())

# convert the object into a dict
akeyless_secret_access_dict = akeyless_secret_access_instance.to_dict()
# create an instance of AkeylessSecretAccess from a dict
akeyless_secret_access_from_dict = AkeylessSecretAccess.from_dict(akeyless_secret_access_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


