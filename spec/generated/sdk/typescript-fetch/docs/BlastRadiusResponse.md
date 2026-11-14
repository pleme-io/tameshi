
# BlastRadiusResponse

Blast radius report for a compromised BLAKE3 hash. Enumerates every node, pod, namespace, and time window where the hash appeared in any CertificationArtifact, plus co-resident artifacts sharing the same Merkle root. 

## Properties

Name | Type
------------ | -------------
`queryHash` | string
`totalAffected` | number
`timeRange` | [BlastRadiusResponseTimeRange](BlastRadiusResponseTimeRange.md)
`affectedNodes` | [Array&lt;AffectedNode&gt;](AffectedNode.md)
`coResidentArtifacts` | [Array&lt;CoResidentArtifact&gt;](CoResidentArtifact.md)
`merkleProof` | [BlastRadiusResponseMerkleProof](BlastRadiusResponseMerkleProof.md)
`chainIntegrity` | boolean
`evidenceHash` | string

## Example

```typescript
import type { BlastRadiusResponse } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "queryHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "totalAffected": null,
  "timeRange": null,
  "affectedNodes": null,
  "coResidentArtifacts": null,
  "merkleProof": null,
  "chainIntegrity": null,
  "evidenceHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
} satisfies BlastRadiusResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as BlastRadiusResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


