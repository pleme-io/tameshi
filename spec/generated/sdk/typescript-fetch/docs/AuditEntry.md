
# AuditEntry

Single entry in the audit trail

## Properties

Name | Type
------------ | -------------
`timestamp` | Date
`action` | [AuditAction](AuditAction.md)
`signature` | string
`details` | string
`resource` | string
`allowed` | boolean

## Example

```typescript
import type { AuditEntry } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "timestamp": null,
  "action": null,
  "signature": null,
  "details": null,
  "resource": null,
  "allowed": null,
} satisfies AuditEntry

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as AuditEntry
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


