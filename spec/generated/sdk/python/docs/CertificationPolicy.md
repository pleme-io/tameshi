# CertificationPolicy

Policy defining certification requirements

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**name** | **str** | Policy name | 
**require_signed_commits** | **bool** | Require all commits to be GPG/SSH signed | [optional] 
**require_pinned_inputs** | **bool** | Require all Nix flake inputs to be pinned | [optional] 
**min_slsa_level** | [**SlsaLevel**](SlsaLevel.md) |  | [optional] 
**require_reproducible** | **bool** | Require builds to be reproducible | [optional] 
**max_critical_high_cves** | **int** | Maximum allowed critical+high CVEs across all builds | [optional] 
**require_image_signatures** | **bool** | Require all container images to have cosign signatures | [optional] 
**require_chart_provenance** | **bool** | Require Helm chart provenance verification | [optional] 
**require_source_verification** | **bool** | Require source commit signature verification | [optional] 
**min_cis_pass_rate** | **float** | Minimum CIS Kubernetes benchmark pass rate (0.0 to 1.0) | [optional] 
**require_network_policies** | **bool** | Require NetworkPolicy resources for all namespaces | [optional] 
**require_compliance** | **bool** | Require compliance assessment to pass | [optional] 

## Example

```python
from tameshi_client.models.certification_policy import CertificationPolicy

# TODO update the JSON string below
json = "{}"
# create an instance of CertificationPolicy from a JSON string
certification_policy_instance = CertificationPolicy.from_json(json)
# print the JSON string representation of the object
print(CertificationPolicy.to_json())

# convert the object into a dict
certification_policy_dict = certification_policy_instance.to_dict()
# create an instance of CertificationPolicy from a dict
certification_policy_from_dict = CertificationPolicy.from_dict(certification_policy_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


