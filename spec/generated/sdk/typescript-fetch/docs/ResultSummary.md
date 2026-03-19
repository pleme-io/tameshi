
# ResultSummary

Abbreviated view of a compliance result

## Properties

Name | Type
------------ | -------------
`id` | string
`environment` | string
`baseline` | [ComplianceBaseline](ComplianceBaseline.md)
`complianceHash` | string
`allSatisfied` | boolean
`totalControls` | number
`satisfied` | number
`notSatisfied` | number
`performedAt` | Date

## Example

```typescript
import type { ResultSummary } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "id": null,
  "environment": null,
  "baseline": null,
  "complianceHash": null,
  "allSatisfied": null,
  "totalControls": null,
  "satisfied": null,
  "notSatisfied": null,
  "performedAt": null,
} satisfies ResultSummary

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ResultSummary
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


