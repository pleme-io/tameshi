# StageStatus

Result of a single certification pipeline stage

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**stage** | **str** | Stage name (e.g. source, build, image, chart, deployment) | 
**passed** | **bool** | Whether the stage passed | 
**hash** | **str** | BLAKE3 hash of the stage attestation data | 
**violations** | **List[str]** | Policy violations found in this stage | 

## Example

```python
from tameshi_client.models.stage_status import StageStatus

# TODO update the JSON string below
json = "{}"
# create an instance of StageStatus from a JSON string
stage_status_instance = StageStatus.from_json(json)
# print the JSON string representation of the object
print(StageStatus.to_json())

# convert the object into a dict
stage_status_dict = stage_status_instance.to_dict()
# create an instance of StageStatus from a dict
stage_status_from_dict = StageStatus.from_dict(stage_status_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


