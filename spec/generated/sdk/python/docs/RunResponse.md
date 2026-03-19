# RunResponse

Response from triggering a compliance assessment

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**status** | **str** | Status of the run (e.g. started, completed) | 
**message** | **str** | Human-readable message about the run | 

## Example

```python
from tameshi_client.models.run_response import RunResponse

# TODO update the JSON string below
json = "{}"
# create an instance of RunResponse from a JSON string
run_response_instance = RunResponse.from_json(json)
# print the JSON string representation of the object
print(RunResponse.to_json())

# convert the object into a dict
run_response_dict = run_response_instance.to_dict()
# create an instance of RunResponse from a dict
run_response_from_dict = RunResponse.from_dict(run_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


