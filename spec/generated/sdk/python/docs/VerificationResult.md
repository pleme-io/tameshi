# VerificationResult

Result of a signature verification

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**passed** | **bool** | Whether verification passed | 
**expected** | **str** | Expected signature or hash value | 
**actual** | **str** | Actual computed signature or hash value | 
**description** | **str** | Human-readable description of what was verified | 
**layer_results** | [**List[LayerVerification]**](LayerVerification.md) | Per-layer verification results | [optional] 

## Example

```python
from tameshi_client.models.verification_result import VerificationResult

# TODO update the JSON string below
json = "{}"
# create an instance of VerificationResult from a JSON string
verification_result_instance = VerificationResult.from_json(json)
# print the JSON string representation of the object
print(VerificationResult.to_json())

# convert the object into a dict
verification_result_dict = verification_result_instance.to_dict()
# create an instance of VerificationResult from a dict
verification_result_from_dict = VerificationResult.from_dict(verification_result_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


