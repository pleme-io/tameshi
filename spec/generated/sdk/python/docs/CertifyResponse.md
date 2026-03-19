# CertifyResponse

Result of the certification pipeline

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**certified** | **bool** | Whether the product passed certification | 
**certification_hash** | **str** | Deterministic BLAKE3 hash of the entire certification | 
**compliance_hash** | **str** | BLAKE3 hash of the compliance dimension | [optional] 
**stages** | [**List[StageStatus]**](StageStatus.md) | Result for each pipeline stage | 
**violations** | **List[str]** | List of policy violations found | 

## Example

```python
from tameshi_client.models.certify_response import CertifyResponse

# TODO update the JSON string below
json = "{}"
# create an instance of CertifyResponse from a JSON string
certify_response_instance = CertifyResponse.from_json(json)
# print the JSON string representation of the object
print(CertifyResponse.to_json())

# convert the object into a dict
certify_response_dict = certify_response_instance.to_dict()
# create an instance of CertifyResponse from a dict
certify_response_from_dict = CertifyResponse.from_dict(certify_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


