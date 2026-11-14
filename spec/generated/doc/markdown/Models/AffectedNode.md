# AffectedNode
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **node** | **String** | Node name | [default to null] |
| **cluster** | **String** | Cluster name (e.g. plo, zek) | [default to null] |
| **first\_execution** | **Date** | Earliest execution of the compromised hash on this node | [default to null] |
| **last\_execution** | **Date** | Most recent execution of the compromised hash on this node | [default to null] |
| **execution\_count** | **Integer** | Total number of verification events involving this hash on this node | [default to null] |
| **pods** | **List** | Pod names that ran the compromised hash | [default to null] |
| **namespaces** | **List** | Namespaces containing pods that ran the compromised hash | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

