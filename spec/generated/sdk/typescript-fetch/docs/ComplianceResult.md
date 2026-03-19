
# ComplianceResult

Full compliance assessment result

## Properties

Name | Type
------------ | -------------
`id` | string
`environment` | string
`baseline` | [ComplianceBaseline](ComplianceBaseline.md)
`frameworkHash` | string
`catalogHash` | string
`assessmentResult` | object
`complianceHash` | string
`allSatisfied` | boolean
`computedAt` | Date

## Example

```typescript
import type { ComplianceResult } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "id": null,
  "environment": null,
  "baseline": null,
  "frameworkHash": null,
  "catalogHash": null,
  "assessmentResult": null,
  "complianceHash": null,
  "allSatisfied": null,
  "computedAt": null,
} satisfies ComplianceResult

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ComplianceResult
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


