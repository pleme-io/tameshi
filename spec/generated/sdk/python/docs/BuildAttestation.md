# BuildAttestation

Attestation of a build artifact

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**service** | **str** | Name of the service that was built | 
**derivation** | **str** | Nix store derivation path | 
**closure_hash** | **str** | BLAKE3 hash of the Nix closure | 
**slsa_level** | [**SlsaLevel**](SlsaLevel.md) |  | 
**reproducible** | **bool** | Whether the build is reproducible | 
**hermetic** | **bool** | Whether the build is hermetic (no network access) | 
**sbom_hash** | **str** | BLAKE3 hash of the software bill of materials | [optional] 
**vuln_scan_hash** | **str** | BLAKE3 hash of vulnerability scan results | [optional] 
**cve_count** | **int** | Total number of CVEs found | [optional] 
**critical_high_cves** | **int** | Number of critical and high severity CVEs | [optional] 
**builder** | **str** | Builder identity (e.g. nix, bazel) | [optional] 
**built_at** | **datetime** | Timestamp when the build completed | [optional] 

## Example

```python
from tameshi_client.models.build_attestation import BuildAttestation

# TODO update the JSON string below
json = "{}"
# create an instance of BuildAttestation from a JSON string
build_attestation_instance = BuildAttestation.from_json(json)
# print the JSON string representation of the object
print(BuildAttestation.to_json())

# convert the object into a dict
build_attestation_dict = build_attestation_instance.to_dict()
# create an instance of BuildAttestation from a dict
build_attestation_from_dict = BuildAttestation.from_dict(build_attestation_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


