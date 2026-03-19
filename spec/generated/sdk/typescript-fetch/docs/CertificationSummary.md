
# CertificationSummary

Abbreviated view of a Certification for list responses

## Properties

Name | Type
------------ | -------------
`name` | string
`namespace` | string
`environment` | string
`phase` | [CertPhase](CertPhase.md)
`gates` | Array&lt;string&gt;
`masterSignature` | string

## Example

```typescript
import type { CertificationSummary } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "name": null,
  "namespace": null,
  "environment": null,
  "phase": null,
  "gates": null,
  "masterSignature": null,
} satisfies CertificationSummary

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as CertificationSummary
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


