
# CertifyResponse

Result of the certification pipeline

## Properties

Name | Type
------------ | -------------
`certified` | boolean
`certificationHash` | string
`complianceHash` | string
`stages` | [Array&lt;StageStatus&gt;](StageStatus.md)
`violations` | Array&lt;string&gt;

## Example

```typescript
import type { CertifyResponse } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "certified": null,
  "certificationHash": null,
  "complianceHash": null,
  "stages": null,
  "violations": null,
} satisfies CertifyResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as CertifyResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


