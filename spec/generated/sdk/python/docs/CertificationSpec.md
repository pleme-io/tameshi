# CertificationSpec

Desired state of a Certification

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**environment** | **str** | Target environment name | 
**gates** | **List[str]** | Names of SignatureGate resources to include | 
**audit_retention_days** | **int** | Number of days to retain audit trail entries | [optional] 

## Example

```python
from tameshi_client.models.certification_spec import CertificationSpec

# TODO update the JSON string below
json = "{}"
# create an instance of CertificationSpec from a JSON string
certification_spec_instance = CertificationSpec.from_json(json)
# print the JSON string representation of the object
print(CertificationSpec.to_json())

# convert the object into a dict
certification_spec_dict = certification_spec_instance.to_dict()
# create an instance of CertificationSpec from a dict
certification_spec_from_dict = CertificationSpec.from_dict(certification_spec_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


