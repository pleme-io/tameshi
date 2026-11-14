# HelmRenderRequest

Request to render and hash a Helm chart

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**chart_path** | **str** | Path to the Helm chart directory or packaged chart | 
**values_files** | **List[str]** | Paths to values files to apply during rendering | [optional] 
**release_name** | **str** | Helm release name to use during rendering | 
**namespace** | **str** | Kubernetes namespace for the rendered output | 

## Example

```python
from tameshi_client.models.helm_render_request import HelmRenderRequest

# TODO update the JSON string below
json = "{}"
# create an instance of HelmRenderRequest from a JSON string
helm_render_request_instance = HelmRenderRequest.from_json(json)
# print the JSON string representation of the object
print(HelmRenderRequest.to_json())

# convert the object into a dict
helm_render_request_dict = helm_render_request_instance.to_dict()
# create an instance of HelmRenderRequest from a dict
helm_render_request_from_dict = HelmRenderRequest.from_dict(helm_render_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


