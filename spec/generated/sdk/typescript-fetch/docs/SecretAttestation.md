
# SecretAttestation

Attestation of secrets-manager secret access during deployment

## Properties

Name | Type
------------ | -------------
`gatewayUrl` | string
`authMethod` | [SecretAuthMethod](SecretAuthMethod.md)
`secretsAccessed` | [Array&lt;SecretAccess&gt;](SecretAccess.md)
`gatewayCertificateHash` | string
`sessionHash` | string

## Example

```typescript
import type { SecretAttestation } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "gatewayUrl": null,
  "authMethod": null,
  "secretsAccessed": null,
  "gatewayCertificateHash": null,
  "sessionHash": null,
} satisfies SecretAttestation

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as SecretAttestation
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


