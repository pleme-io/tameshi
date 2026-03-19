
# InputHash

Hash of a single input artifact within a layer

## Properties

Name | Type
------------ | -------------
`name` | string
`hash` | string
`size` | number

## Example

```typescript
import type { InputHash } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "name": null,
  "hash": null,
  "size": null,
} satisfies InputHash

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as InputHash
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


