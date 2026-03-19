# SignatureMetadata

Metadata about a signature computation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**computed_at** | **datetime** | Timestamp when the signature was computed | 
**collector_version** | **str** | Version of the collector that produced this signature | 
**source** | **str** | Identifier for the source that produced the inputs | 
**environment** | **str** | Environment context for the computation | [optional] 

## Example

```python
from tameshi_client.models.signature_metadata import SignatureMetadata

# TODO update the JSON string below
json = "{}"
# create an instance of SignatureMetadata from a JSON string
signature_metadata_instance = SignatureMetadata.from_json(json)
# print the JSON string representation of the object
print(SignatureMetadata.to_json())

# convert the object into a dict
signature_metadata_dict = signature_metadata_instance.to_dict()
# create an instance of SignatureMetadata from a dict
signature_metadata_from_dict = SignatureMetadata.from_dict(signature_metadata_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


