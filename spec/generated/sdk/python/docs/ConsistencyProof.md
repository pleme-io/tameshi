# ConsistencyProof

Proof that a chain prefix is consistent with a later chain state

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**from_seq** | **int** | Sequence number of the earlier chain state | 
**to_seq** | **int** | Sequence number of the later chain state | 
**from_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**to_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**proof_nodes** | **List[str]** | BLAKE3 intermediate hashes forming the consistency proof | 
**verified** | **bool** | Whether the proof has been verified server-side | 

## Example

```python
from tameshi_client.models.consistency_proof import ConsistencyProof

# TODO update the JSON string below
json = "{}"
# create an instance of ConsistencyProof from a JSON string
consistency_proof_instance = ConsistencyProof.from_json(json)
# print the JSON string representation of the object
print(ConsistencyProof.to_json())

# convert the object into a dict
consistency_proof_dict = consistency_proof_instance.to_dict()
# create an instance of ConsistencyProof from a dict
consistency_proof_from_dict = ConsistencyProof.from_dict(consistency_proof_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


