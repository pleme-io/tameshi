# AffectedNode

A node where the compromised hash was active during the queried window

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**node** | **str** | Node name | 
**cluster** | **str** | Cluster name (e.g. plo, zek) | 
**first_execution** | **datetime** | Earliest execution of the compromised hash on this node | 
**last_execution** | **datetime** | Most recent execution of the compromised hash on this node | 
**execution_count** | **int** | Total number of verification events involving this hash on this node | 
**pods** | **List[str]** | Pod names that ran the compromised hash | 
**namespaces** | **List[str]** | Namespaces containing pods that ran the compromised hash | 

## Example

```python
from tameshi_client.models.affected_node import AffectedNode

# TODO update the JSON string below
json = "{}"
# create an instance of AffectedNode from a JSON string
affected_node_instance = AffectedNode.from_json(json)
# print the JSON string representation of the object
print(AffectedNode.to_json())

# convert the object into a dict
affected_node_dict = affected_node_instance.to_dict()
# create an instance of AffectedNode from a dict
affected_node_from_dict = AffectedNode.from_dict(affected_node_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


