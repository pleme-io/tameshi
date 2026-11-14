# \SigningAPI

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SignMerkleRoot**](SigningAPI.md#SignMerkleRoot) | **Post** /api/v1/signing/sign | Sign a Merkle root
[**VerifySignedRoot**](SigningAPI.md#VerifySignedRoot) | **Post** /api/v1/signing/verify | Verify a signed root



## SignMerkleRoot

> SignedRoot SignMerkleRoot(ctx).SignRequest(signRequest).Execute()

Sign a Merkle root



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/GIT_USER_ID/GIT_REPO_ID/tameshi"
)

func main() {
	signRequest := *openapiclient.NewSignRequest("blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", openapiclient.SigningAlgorithm("ed25519_local")) // SignRequest | 

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.SigningAPI.SignMerkleRoot(context.Background()).SignRequest(signRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `SigningAPI.SignMerkleRoot``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `SignMerkleRoot`: SignedRoot
	fmt.Fprintf(os.Stdout, "Response from `SigningAPI.SignMerkleRoot`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiSignMerkleRootRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **signRequest** | [**SignRequest**](SignRequest.md) |  | 

### Return type

[**SignedRoot**](SignedRoot.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## VerifySignedRoot

> VerifySignedRoot200Response VerifySignedRoot(ctx).SignedRoot(signedRoot).Execute()

Verify a signed root



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
    "time"
	openapiclient "github.com/GIT_USER_ID/GIT_REPO_ID/tameshi"
)

func main() {
	signedRoot := *openapiclient.NewSignedRoot("blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "Signature_example", openapiclient.SigningAlgorithm("ed25519_local"), "SignerId_example", time.Now()) // SignedRoot | 

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.SigningAPI.VerifySignedRoot(context.Background()).SignedRoot(signedRoot).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `SigningAPI.VerifySignedRoot``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `VerifySignedRoot`: VerifySignedRoot200Response
	fmt.Fprintf(os.Stdout, "Response from `SigningAPI.VerifySignedRoot`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiVerifySignedRootRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **signedRoot** | [**SignedRoot**](SignedRoot.md) |  | 

### Return type

[**VerifySignedRoot200Response**](VerifySignedRoot200Response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

