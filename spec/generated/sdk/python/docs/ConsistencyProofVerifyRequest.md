# ConsistencyProofVerifyRequest

Request to verify a heartbeat consistency proof

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**proof** | [**ConsistencyProof**](ConsistencyProof.md) |  | 
**expected_from_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**expected_to_hash** | **str** | BLAKE3 hash in prefixed hex format | 

## Example

```python
from tameshi_client.models.consistency_proof_verify_request import ConsistencyProofVerifyRequest

# TODO update the JSON string below
json = "{}"
# create an instance of ConsistencyProofVerifyRequest from a JSON string
consistency_proof_verify_request_instance = ConsistencyProofVerifyRequest.from_json(json)
# print the JSON string representation of the object
print(ConsistencyProofVerifyRequest.to_json())

# convert the object into a dict
consistency_proof_verify_request_dict = consistency_proof_verify_request_instance.to_dict()
# create an instance of ConsistencyProofVerifyRequest from a dict
consistency_proof_verify_request_from_dict = ConsistencyProofVerifyRequest.from_dict(consistency_proof_verify_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


