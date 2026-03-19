# ImageAttestation

Attestation of a container image

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**image_ref** | **str** | Full image reference (registry/repo) | 
**tag** | **str** | Image tag | 
**architecture** | **str** | Target CPU architecture (e.g. amd64, arm64) | 
**manifest_hash** | **str** | OCI manifest digest | 
**cosign_verified** | **bool** | Whether the image signature was verified with cosign | 
**signer_identity** | **str** | Identity of the cosign signer | [optional] 
**vuln_scan_hash** | **str** | BLAKE3 hash of vulnerability scan results | [optional] 
**vuln_count** | **int** | Total number of vulnerabilities found | [optional] 
**critical_high_vulns** | **int** | Number of critical and high severity vulnerabilities | [optional] 
**sbom_hash** | **str** | BLAKE3 hash of the image SBOM | [optional] 

## Example

```python
from tameshi_client.models.image_attestation import ImageAttestation

# TODO update the JSON string below
json = "{}"
# create an instance of ImageAttestation from a JSON string
image_attestation_instance = ImageAttestation.from_json(json)
# print the JSON string representation of the object
print(ImageAttestation.to_json())

# convert the object into a dict
image_attestation_dict = image_attestation_instance.to_dict()
# create an instance of ImageAttestation from a dict
image_attestation_from_dict = ImageAttestation.from_dict(image_attestation_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


