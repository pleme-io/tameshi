# SigningApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**signMerkleRoot**](SigningApi.md#signmerkleroot) | **POST** /api/v1/signing/sign | Sign a Merkle root |
| [**verifySignedRoot**](SigningApi.md#verifysignedroot) | **POST** /api/v1/signing/verify | Verify a signed root |



## signMerkleRoot

> SignedRoot signMerkleRoot(signRequest)

Sign a Merkle root

Signs a BLAKE3 Merkle root using the specified algorithm. Supports local Ed25519 signing and remote Fragment signing for remote key management. 

### Example

```ts
import {
  Configuration,
  SigningApi,
} from '@tameshi/client';
import type { SignMerkleRootRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new SigningApi();

  const body = {
    // SignRequest
    signRequest: ...,
  } satisfies SignMerkleRootRequest;

  try {
    const data = await api.signMerkleRoot(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **signRequest** | [SignRequest](SignRequest.md) |  | |

### Return type

[**SignedRoot**](SignedRoot.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Signed root with signature and signer metadata |  -  |
| **400** | Invalid request |  -  |
| **500** | Signing operation failed |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## verifySignedRoot

> VerifySignedRoot200Response verifySignedRoot(signedRoot)

Verify a signed root

Verifies the signature on a signed Merkle root. The algorithm and key identity are embedded in the SignedRoot object. 

### Example

```ts
import {
  Configuration,
  SigningApi,
} from '@tameshi/client';
import type { VerifySignedRootRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new SigningApi();

  const body = {
    // SignedRoot
    signedRoot: ...,
  } satisfies VerifySignedRootRequest;

  try {
    const data = await api.verifySignedRoot(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **signedRoot** | [SignedRoot](SignedRoot.md) |  | |

### Return type

[**VerifySignedRoot200Response**](VerifySignedRoot200Response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Verification result |  -  |
| **400** | Invalid signed root |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

