# BlastRadiusResponseTimeRange


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**first_seen** | **datetime** | Earliest timestamp the hash was observed in the ledger | 
**last_seen** | **datetime** | Most recent timestamp the hash was observed in the ledger | 

## Example

```python
from tameshi_client.models.blast_radius_response_time_range import BlastRadiusResponseTimeRange

# TODO update the JSON string below
json = "{}"
# create an instance of BlastRadiusResponseTimeRange from a JSON string
blast_radius_response_time_range_instance = BlastRadiusResponseTimeRange.from_json(json)
# print the JSON string representation of the object
print(BlastRadiusResponseTimeRange.to_json())

# convert the object into a dict
blast_radius_response_time_range_dict = blast_radius_response_time_range_instance.to_dict()
# create an instance of BlastRadiusResponseTimeRange from a dict
blast_radius_response_time_range_from_dict = BlastRadiusResponseTimeRange.from_dict(blast_radius_response_time_range_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


