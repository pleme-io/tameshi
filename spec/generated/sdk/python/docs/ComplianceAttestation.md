# ComplianceAttestation

Multi-dimensional compliance attestation for a deployment artifact

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**environment** | **str** | Environment being attested | 
**artifact** | **str** | Artifact identifier being attested | 
**dimensions** | [**List[ComplianceDimension]**](ComplianceDimension.md) | Individual compliance dimensions assessed | 
**compliance_hash** | **str** | BLAKE3 hash of all dimension results combined | 
**computed_at** | **datetime** | When the attestation was computed | 
**policy_name** | **str** | Name of the policy applied | 
**all_passed** | **bool** | Whether all required dimensions passed | 

## Example

```python
from tameshi_client.models.compliance_attestation import ComplianceAttestation

# TODO update the JSON string below
json = "{}"
# create an instance of ComplianceAttestation from a JSON string
compliance_attestation_instance = ComplianceAttestation.from_json(json)
# print the JSON string representation of the object
print(ComplianceAttestation.to_json())

# convert the object into a dict
compliance_attestation_dict = compliance_attestation_instance.to_dict()
# create an instance of ComplianceAttestation from a dict
compliance_attestation_from_dict = ComplianceAttestation.from_dict(compliance_attestation_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


