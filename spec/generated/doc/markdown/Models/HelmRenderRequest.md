# HelmRenderRequest
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **chartPath** | **String** | Path to the Helm chart directory or packaged chart | [default to null] |
| **valuesFiles** | **List** | Paths to values files to apply during rendering | [optional] [default to null] |
| **releaseName** | **String** | Helm release name to use during rendering | [default to null] |
| **namespace** | **String** | Kubernetes namespace for the rendered output | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

