# \HeartbeatAPI

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetHeartbeatChain**](HeartbeatAPI.md#GetHeartbeatChain) | **Get** /api/v1/heartbeat/chain | Get heartbeat chain entries
[**GetHeartbeatConsistencyProof**](HeartbeatAPI.md#GetHeartbeatConsistencyProof) | **Get** /api/v1/heartbeat/consistency-proof | Get consistency proof between two chain states
[**VerifyHeartbeatConsistencyProof**](HeartbeatAPI.md#VerifyHeartbeatConsistencyProof) | **Post** /api/v1/heartbeat/verify | Verify a consistency proof



## GetHeartbeatChain

> []HeartbeatEntry GetHeartbeatChain(ctx).FromSeq(fromSeq).ToSeq(toSeq).Limit(limit).Execute()

Get heartbeat chain entries



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
	fromSeq := int64(789) // int64 | Starting sequence number (inclusive) (optional)
	toSeq := int64(789) // int64 | Ending sequence number (inclusive) (optional)
	limit := int32(56) // int32 | Maximum number of entries to return (optional) (default to 100)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.HeartbeatAPI.GetHeartbeatChain(context.Background()).FromSeq(fromSeq).ToSeq(toSeq).Limit(limit).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `HeartbeatAPI.GetHeartbeatChain``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetHeartbeatChain`: []HeartbeatEntry
	fmt.Fprintf(os.Stdout, "Response from `HeartbeatAPI.GetHeartbeatChain`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetHeartbeatChainRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **fromSeq** | **int64** | Starting sequence number (inclusive) | 
 **toSeq** | **int64** | Ending sequence number (inclusive) | 
 **limit** | **int32** | Maximum number of entries to return | [default to 100]

### Return type

[**[]HeartbeatEntry**](HeartbeatEntry.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetHeartbeatConsistencyProof

> ConsistencyProof GetHeartbeatConsistencyProof(ctx).FromSeq(fromSeq).ToSeq(toSeq).Execute()

Get consistency proof between two chain states



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
	fromSeq := int64(789) // int64 | Earlier sequence number
	toSeq := int64(789) // int64 | Later sequence number

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.HeartbeatAPI.GetHeartbeatConsistencyProof(context.Background()).FromSeq(fromSeq).ToSeq(toSeq).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `HeartbeatAPI.GetHeartbeatConsistencyProof``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetHeartbeatConsistencyProof`: ConsistencyProof
	fmt.Fprintf(os.Stdout, "Response from `HeartbeatAPI.GetHeartbeatConsistencyProof`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetHeartbeatConsistencyProofRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **fromSeq** | **int64** | Earlier sequence number | 
 **toSeq** | **int64** | Later sequence number | 

### Return type

[**ConsistencyProof**](ConsistencyProof.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## VerifyHeartbeatConsistencyProof

> VerifyHeartbeatConsistencyProof200Response VerifyHeartbeatConsistencyProof(ctx).ConsistencyProofVerifyRequest(consistencyProofVerifyRequest).Execute()

Verify a consistency proof



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
	consistencyProofVerifyRequest := *openapiclient.NewConsistencyProofVerifyRequest(*openapiclient.NewConsistencyProof(int64(123), int64(123), "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", []string{"ProofNodes_example"}, false), "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262") // ConsistencyProofVerifyRequest | 

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.HeartbeatAPI.VerifyHeartbeatConsistencyProof(context.Background()).ConsistencyProofVerifyRequest(consistencyProofVerifyRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `HeartbeatAPI.VerifyHeartbeatConsistencyProof``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `VerifyHeartbeatConsistencyProof`: VerifyHeartbeatConsistencyProof200Response
	fmt.Fprintf(os.Stdout, "Response from `HeartbeatAPI.VerifyHeartbeatConsistencyProof`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiVerifyHeartbeatConsistencyProofRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **consistencyProofVerifyRequest** | [**ConsistencyProofVerifyRequest**](ConsistencyProofVerifyRequest.md) |  | 

### Return type

[**VerifyHeartbeatConsistencyProof200Response**](VerifyHeartbeatConsistencyProof200Response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

