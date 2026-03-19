# CertifyRequest

Request to certify a product deployment through the multi-stage pipeline

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**product** | **str** | Product name being certified | 
**environment** | **str** | Target environment (e.g. plo, zek) | 
**cluster** | **str** | Kubernetes cluster name | 
**source** | [**SourceAttestation**](SourceAttestation.md) |  | 
**builds** | [**List[BuildAttestation]**](BuildAttestation.md) | Build attestations for each service | 
**images** | [**List[ImageAttestation]**](ImageAttestation.md) | Container image attestations | 
**charts** | [**List[ChartAttestation]**](ChartAttestation.md) | Helm chart attestations | 
**deployment** | [**DeploymentAttestation**](DeploymentAttestation.md) |  | 
**policy** | **str** | Name of the CertificationPolicy to evaluate against | [optional] [default to 'default']

## Example

```python
from tameshi_client.models.certify_request import CertifyRequest

# TODO update the JSON string below
json = "{}"
# create an instance of CertifyRequest from a JSON string
certify_request_instance = CertifyRequest.from_json(json)
# print the JSON string representation of the object
print(CertifyRequest.to_json())

# convert the object into a dict
certify_request_dict = certify_request_instance.to_dict()
# create an instance of CertifyRequest from a dict
certify_request_from_dict = CertifyRequest.from_dict(certify_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


