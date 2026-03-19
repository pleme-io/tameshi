
# CertifyRequest

Request to certify a product deployment through the multi-stage pipeline

## Properties

Name | Type
------------ | -------------
`product` | string
`environment` | string
`cluster` | string
`source` | [SourceAttestation](SourceAttestation.md)
`builds` | [Array&lt;BuildAttestation&gt;](BuildAttestation.md)
`images` | [Array&lt;ImageAttestation&gt;](ImageAttestation.md)
`charts` | [Array&lt;ChartAttestation&gt;](ChartAttestation.md)
`deployment` | [DeploymentAttestation](DeploymentAttestation.md)
`policy` | string

## Example

```typescript
import type { CertifyRequest } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "product": null,
  "environment": null,
  "cluster": null,
  "source": null,
  "builds": null,
  "images": null,
  "charts": null,
  "deployment": null,
  "policy": null,
} satisfies CertifyRequest

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as CertifyRequest
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


