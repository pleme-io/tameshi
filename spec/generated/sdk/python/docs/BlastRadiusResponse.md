# BlastRadiusResponse

Blast radius report for a compromised BLAKE3 hash. Enumerates every node, pod, namespace, and time window where the hash appeared in any CertificationArtifact, plus co-resident artifacts sharing the same Merkle root. 

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**query_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**total_affected** | **int** | Total number of affected nodes | 
**time_range** | [**BlastRadiusResponseTimeRange**](BlastRadiusResponseTimeRange.md) |  | 
**affected_nodes** | [**List[AffectedNode]**](AffectedNode.md) | List of nodes where the compromised hash was active | 
**co_resident_artifacts** | [**List[CoResidentArtifact]**](CoResidentArtifact.md) | Other artifacts that shared the same Merkle root as the compromised hash | 
**merkle_proof** | [**BlastRadiusResponseMerkleProof**](BlastRadiusResponseMerkleProof.md) |  | [optional] 
**chain_integrity** | **bool** | Whether the ledger hash chain is intact for the queried range | 
**evidence_hash** | **str** | BLAKE3 hash in prefixed hex format | 

## Example

```python
from tameshi_client.models.blast_radius_response import BlastRadiusResponse

# TODO update the JSON string below
json = "{}"
# create an instance of BlastRadiusResponse from a JSON string
blast_radius_response_instance = BlastRadiusResponse.from_json(json)
# print the JSON string representation of the object
print(BlastRadiusResponse.to_json())

# convert the object into a dict
blast_radius_response_dict = blast_radius_response_instance.to_dict()
# create an instance of BlastRadiusResponse from a dict
blast_radius_response_from_dict = BlastRadiusResponse.from_dict(blast_radius_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


