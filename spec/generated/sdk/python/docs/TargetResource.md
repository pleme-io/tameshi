# TargetResource

Kubernetes resource targeted by a gate for admission control

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**group** | **str** | API group (e.g. apps, batch, empty string for core) | 
**kind** | **str** | Resource kind (e.g. Deployment, Job) | 
**operations** | **List[str]** | Admission operations to intercept (CREATE, UPDATE, DELETE) | 

## Example

```python
from tameshi_client.models.target_resource import TargetResource

# TODO update the JSON string below
json = "{}"
# create an instance of TargetResource from a JSON string
target_resource_instance = TargetResource.from_json(json)
# print the JSON string representation of the object
print(TargetResource.to_json())

# convert the object into a dict
target_resource_dict = target_resource_instance.to_dict()
# create an instance of TargetResource from a dict
target_resource_from_dict = TargetResource.from_dict(target_resource_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


