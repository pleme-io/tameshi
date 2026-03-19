# ComplianceDimension

A single compliance dimension within an attestation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**dimension_type** | [**DimensionType**](DimensionType.md) |  | 
**hash** | **str** | BLAKE3 hash of the dimension assessment data | 
**passed** | **bool** | Whether this dimension passed | 
**summary** | **str** | Human-readable summary of the assessment | 
**assessed_at** | **datetime** | When this dimension was assessed | 
**required** | **bool** | Whether this dimension is required for certification | 

## Example

```python
from tameshi_client.models.compliance_dimension import ComplianceDimension

# TODO update the JSON string below
json = "{}"
# create an instance of ComplianceDimension from a JSON string
compliance_dimension_instance = ComplianceDimension.from_json(json)
# print the JSON string representation of the object
print(ComplianceDimension.to_json())

# convert the object into a dict
compliance_dimension_dict = compliance_dimension_instance.to_dict()
# create an instance of ComplianceDimension from a dict
compliance_dimension_from_dict = ComplianceDimension.from_dict(compliance_dimension_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


