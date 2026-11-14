
# ProvenanceResponseActiveArtifactsInnerDeploymentContext

Deployment context at the queried timestamp

## Properties

Name | Type
------------ | -------------
`cluster` | string
`namespace` | string
`node` | string
`pod` | string
`container` | string
`imageRef` | string
`binaryPaths` | Array&lt;string&gt;
`sdlcChainHash` | string
`complianceReportHash` | string

## Example

```typescript
import type { ProvenanceResponseActiveArtifactsInnerDeploymentContext } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "cluster": null,
  "namespace": null,
  "node": null,
  "pod": null,
  "container": null,
  "imageRef": null,
  "binaryPaths": null,
  "sdlcChainHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "complianceReportHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
} satisfies ProvenanceResponseActiveArtifactsInnerDeploymentContext

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ProvenanceResponseActiveArtifactsInnerDeploymentContext
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


