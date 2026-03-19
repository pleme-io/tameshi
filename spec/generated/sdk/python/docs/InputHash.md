# InputHash

Hash of a single input artifact within a layer

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**name** | **str** | Logical name of the input artifact | 
**hash** | **str** | BLAKE3 hash of the input content | 
**size** | **int** | Size of the input in bytes | [optional] 

## Example

```python
from tameshi_client.models.input_hash import InputHash

# TODO update the JSON string below
json = "{}"
# create an instance of InputHash from a JSON string
input_hash_instance = InputHash.from_json(json)
# print the JSON string representation of the object
print(InputHash.to_json())

# convert the object into a dict
input_hash_dict = input_hash_instance.to_dict()
# create an instance of InputHash from a dict
input_hash_from_dict = InputHash.from_dict(input_hash_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


