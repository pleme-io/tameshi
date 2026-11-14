# NodeBlastRadius

Per-node blast radius detail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**node** | **str** | Node identifier | 
**pods** | **List[str]** | Affected pods on this node | 
**binary_paths** | **List[str]** | Binary paths containing the compromised artifact | 
**first_execution** | **datetime** | First execution on this node | 
**last_execution** | **datetime** | Most recent execution on this node | 
**execution_count** | **int** | Total execution count | 

## Example

```python
from tameshi_client.models.node_blast_radius import NodeBlastRadius

# TODO update the JSON string below
json = "{}"
# create an instance of NodeBlastRadius from a JSON string
node_blast_radius_instance = NodeBlastRadius.from_json(json)
# print the JSON string representation of the object
print(NodeBlastRadius.to_json())

# convert the object into a dict
node_blast_radius_dict = node_blast_radius_instance.to_dict()
# create an instance of NodeBlastRadius from a dict
node_blast_radius_from_dict = NodeBlastRadius.from_dict(node_blast_radius_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


