# ProvenanceResponse_active_artifacts_inner_deployment_context
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **cluster** | **String** | Kubernetes cluster name | [default to null] |
| **namespace** | **String** | Kubernetes namespace | [default to null] |
| **node** | **String** | Node name | [default to null] |
| **pod** | **String** | Pod name | [default to null] |
| **container** | **String** | Container name | [default to null] |
| **image\_ref** | **String** | Full container image reference | [default to null] |
| **binary\_paths** | **List** | Nix store paths or binary paths within the container | [default to null] |
| **sdlc\_chain\_hash** | **String** | BLAKE3 hash in prefixed hex format | [optional] [default to null] |
| **compliance\_report\_hash** | **String** | BLAKE3 hash in prefixed hex format | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

