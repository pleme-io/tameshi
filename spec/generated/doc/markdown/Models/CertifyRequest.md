# CertifyRequest
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **product** | **String** | Product name being certified | [default to null] |
| **environment** | **String** | Target environment (e.g. plo, zek) | [default to null] |
| **cluster** | **String** | Kubernetes cluster name | [default to null] |
| **source** | [**SourceAttestation**](SourceAttestation.md) |  | [default to null] |
| **builds** | [**List**](BuildAttestation.md) | Build attestations for each service | [default to null] |
| **images** | [**List**](ImageAttestation.md) | Container image attestations | [default to null] |
| **charts** | [**List**](ChartAttestation.md) | Helm chart attestations | [default to null] |
| **deployment** | [**DeploymentAttestation**](DeploymentAttestation.md) |  | [default to null] |
| **policy** | **String** | Name of the CertificationPolicy to evaluate against | [optional] [default to default] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

