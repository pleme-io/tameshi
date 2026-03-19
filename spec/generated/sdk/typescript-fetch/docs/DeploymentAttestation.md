
# DeploymentAttestation

Attestation of a Kubernetes deployment

## Properties

Name | Type
------------ | -------------
`namespace` | string
`kustomization` | string
`sourceCommit` | string
`sourceVerified` | boolean
`manifestHash` | string
`allReleasesSigned` | boolean
`cisK8sPassRate` | number
`networkPoliciesVerified` | boolean
`runningPods` | number
`allHealthy` | boolean

## Example

```typescript
import type { DeploymentAttestation } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "namespace": null,
  "kustomization": null,
  "sourceCommit": null,
  "sourceVerified": null,
  "manifestHash": null,
  "allReleasesSigned": null,
  "cisK8sPassRate": null,
  "networkPoliciesVerified": null,
  "runningPods": null,
  "allHealthy": null,
} satisfies DeploymentAttestation

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as DeploymentAttestation
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


