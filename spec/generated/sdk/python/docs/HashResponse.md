# HashResponse

Latest compliance hash information

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**compliance_hash** | **str** | BLAKE3 hash of the most recent compliance assessment | 
**environment** | **str** | Environment of the assessment | 
**baseline** | [**ComplianceBaseline**](ComplianceBaseline.md) |  | 
**computed_at** | **datetime** | When the hash was computed | 

## Example

```python
from tameshi_client.models.hash_response import HashResponse

# TODO update the JSON string below
json = "{}"
# create an instance of HashResponse from a JSON string
hash_response_instance = HashResponse.from_json(json)
# print the JSON string representation of the object
print(HashResponse.to_json())

# convert the object into a dict
hash_response_dict = hash_response_instance.to_dict()
# create an instance of HashResponse from a dict
hash_response_from_dict = HashResponse.from_dict(hash_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


