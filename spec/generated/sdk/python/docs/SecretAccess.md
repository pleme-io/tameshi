# SecretAccess

Record of a single secrets-manager secret access

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**path** | **str** | Secrets-manager secret path | 
**secret_type** | [**SecretKind**](SecretKind.md) |  | 
**value_hash** | **str** | BLAKE3 hash of the secret value (not the secret itself) | 
**accessed_at** | **datetime** | Timestamp when the secret was accessed | 
**version** | **int** | Secret version number | [optional] 

## Example

```python
from tameshi_client.models.secret_access import SecretAccess

# TODO update the JSON string below
json = "{}"
# create an instance of SecretAccess from a JSON string
secret_access_instance = SecretAccess.from_json(json)
# print the JSON string representation of the object
print(SecretAccess.to_json())

# convert the object into a dict
secret_access_dict = secret_access_instance.to_dict()
# create an instance of SecretAccess from a dict
secret_access_from_dict = SecretAccess.from_dict(secret_access_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


