# HeartbeatEntry

Single entry in the heartbeat proof chain

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sequence** | **int** | Monotonically increasing sequence number | 
**timestamp** | **datetime** | When the heartbeat event occurred | 
**verifier** | [**VerifierIdentity**](VerifierIdentity.md) |  | 
**event** | [**HeartbeatEvent**](HeartbeatEvent.md) |  | 
**result** | [**VerificationOutcome**](VerificationOutcome.md) |  | 
**resource** | **str** | Identifier of the resource involved (e.g. apps/v1/Deployment/my-app) | 
**signature_checked** | **str** | BLAKE3 signature hash that was checked during this event | 
**entry_hash** | **str** | BLAKE3 hash in prefixed hex format | 
**previous_hash** | **str** | BLAKE3 hash in prefixed hex format | 

## Example

```python
from tameshi_client.models.heartbeat_entry import HeartbeatEntry

# TODO update the JSON string below
json = "{}"
# create an instance of HeartbeatEntry from a JSON string
heartbeat_entry_instance = HeartbeatEntry.from_json(json)
# print the JSON string representation of the object
print(HeartbeatEntry.to_json())

# convert the object into a dict
heartbeat_entry_dict = heartbeat_entry_instance.to_dict()
# create an instance of HeartbeatEntry from a dict
heartbeat_entry_from_dict = HeartbeatEntry.from_dict(heartbeat_entry_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


