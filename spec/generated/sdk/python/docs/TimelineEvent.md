# TimelineEvent

A single verification event in the forensics timeline

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**timestamp** | **datetime** | When the verification event occurred | 
**event_type** | [**HeartbeatEvent**](HeartbeatEvent.md) |  | 
**decision** | [**VerificationOutcome**](VerificationOutcome.md) |  | 
**node** | **str** | Node where the event occurred | 
**pod** | **str** | Pod that triggered the event | 
**binary_path** | **str** | Path of the binary being verified | 
**composed_root** | **str** | BLAKE3 hash in prefixed hex format | 
**sequence** | **int** | Ledger sequence number for this event | 

## Example

```python
from tameshi_client.models.timeline_event import TimelineEvent

# TODO update the JSON string below
json = "{}"
# create an instance of TimelineEvent from a JSON string
timeline_event_instance = TimelineEvent.from_json(json)
# print the JSON string representation of the object
print(TimelineEvent.to_json())

# convert the object into a dict
timeline_event_dict = timeline_event_instance.to_dict()
# create an instance of TimelineEvent from a dict
timeline_event_from_dict = TimelineEvent.from_dict(timeline_event_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


