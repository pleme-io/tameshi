# CertificationSummary

Abbreviated view of a Certification for list responses

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**name** | **str** | Name of the Certification resource | 
**namespace** | **str** | Kubernetes namespace | 
**environment** | **str** | Target environment (e.g. plo, zek) | 
**phase** | [**CertPhase**](CertPhase.md) |  | 
**gates** | **List[str]** | Names of the SignatureGates included in this certification | [optional] 
**master_signature** | **str** | Composite master signature across all gates | [optional] 

## Example

```python
from tameshi_client.models.certification_summary import CertificationSummary

# TODO update the JSON string below
json = "{}"
# create an instance of CertificationSummary from a JSON string
certification_summary_instance = CertificationSummary.from_json(json)
# print the JSON string representation of the object
print(CertificationSummary.to_json())

# convert the object into a dict
certification_summary_dict = certification_summary_instance.to_dict()
# create an instance of CertificationSummary from a dict
certification_summary_from_dict = CertificationSummary.from_dict(certification_summary_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


