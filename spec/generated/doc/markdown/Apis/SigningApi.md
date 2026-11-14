# SigningApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**signMerkleRoot**](SigningApi.md#signMerkleRoot) | **POST** /api/v1/signing/sign | Sign a Merkle root |
| [**verifySignedRoot**](SigningApi.md#verifySignedRoot) | **POST** /api/v1/signing/verify | Verify a signed root |


<a name="signMerkleRoot"></a>
# **signMerkleRoot**
> SignedRoot signMerkleRoot(SignRequest)

Sign a Merkle root

    Signs a BLAKE3 Merkle root using the specified algorithm. Supports local Ed25519 signing and remote Fragment signing for remote key management. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **SignRequest** | [**SignRequest**](../Models/SignRequest.md)|  | |

### Return type

[**SignedRoot**](../Models/SignedRoot.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

<a name="verifySignedRoot"></a>
# **verifySignedRoot**
> verifySignedRoot_200_response verifySignedRoot(SignedRoot)

Verify a signed root

    Verifies the signature on a signed Merkle root. The algorithm and key identity are embedded in the SignedRoot object. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **SignedRoot** | [**SignedRoot**](../Models/SignedRoot.md)|  | |

### Return type

[**verifySignedRoot_200_response**](../Models/verifySignedRoot_200_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

