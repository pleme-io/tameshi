# ChartAttestation

Attestation of a Helm chart

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**chart_name** | **str** | Helm chart name | 
**chart_version** | **str** | Helm chart version | 
**chart_hash** | **str** | BLAKE3 hash of the packaged chart | 
**provenance_verified** | **bool** | Whether the chart provenance file was verified | 
**dependency_hashes** | **List[str]** | BLAKE3 hashes of chart dependencies | [optional] 
**linter_passed** | **bool** | Whether the chart passed helm lint | 
**policy_passed** | **bool** | Whether the chart passed OPA/Kyverno policies | 
**registry_ref** | **str** | OCI registry reference for the chart | [optional] 

## Example

```python
from tameshi_client.models.chart_attestation import ChartAttestation

# TODO update the JSON string below
json = "{}"
# create an instance of ChartAttestation from a JSON string
chart_attestation_instance = ChartAttestation.from_json(json)
# print the JSON string representation of the object
print(ChartAttestation.to_json())

# convert the object into a dict
chart_attestation_dict = chart_attestation_instance.to_dict()
# create an instance of ChartAttestation from a dict
chart_attestation_from_dict = ChartAttestation.from_dict(chart_attestation_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


