# BlastRadiusResponseMerkleProof

Inclusion proof for the compromised hash in its Merkle tree

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**leaf_index** | **int** | Index of the compromised hash leaf in the Merkle tree | [optional] 
**proof_nodes** | **List[str]** | BLAKE3 intermediate hashes forming the inclusion proof | [optional] 

## Example

```python
from tameshi_client.models.blast_radius_response_merkle_proof import BlastRadiusResponseMerkleProof

# TODO update the JSON string below
json = "{}"
# create an instance of BlastRadiusResponseMerkleProof from a JSON string
blast_radius_response_merkle_proof_instance = BlastRadiusResponseMerkleProof.from_json(json)
# print the JSON string representation of the object
print(BlastRadiusResponseMerkleProof.to_json())

# convert the object into a dict
blast_radius_response_merkle_proof_dict = blast_radius_response_merkle_proof_instance.to_dict()
# create an instance of BlastRadiusResponseMerkleProof from a dict
blast_radius_response_merkle_proof_from_dict = BlastRadiusResponseMerkleProof.from_dict(blast_radius_response_merkle_proof_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


