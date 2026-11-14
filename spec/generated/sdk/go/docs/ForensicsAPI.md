# \ForensicsAPI

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetBlastRadius**](ForensicsAPI.md#GetBlastRadius) | **Get** /api/v1/forensics/blast-radius | Query blast radius for a compromised hash
[**GetForensicsProvenance**](ForensicsAPI.md#GetForensicsProvenance) | **Get** /api/v1/forensics/provenance | Get point-in-time artifact stack for a node
[**GetForensicsTimeline**](ForensicsAPI.md#GetForensicsTimeline) | **Get** /api/v1/forensics/timeline | Get chronological event stream for a hash
[**RevokeHash**](ForensicsAPI.md#RevokeHash) | **Post** /api/v1/forensics/revoke | Emergency revocation of a compromised hash



## GetBlastRadius

> BlastRadiusResponse GetBlastRadius(ctx).Hash(hash).From(from).To(to).Execute()

Query blast radius for a compromised hash



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
	hash := "hash_example" // string | BLAKE3 hash of the compromised artifact (prefixed, e.g. blake3:abc...)
	from := time.Now() // time.Time | Start of the time window (default 72 hours ago) (optional)
	to := time.Now() // time.Time | End of the time window (default now) (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ForensicsAPI.GetBlastRadius(context.Background()).Hash(hash).From(from).To(to).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ForensicsAPI.GetBlastRadius``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetBlastRadius`: BlastRadiusResponse
	fmt.Fprintf(os.Stdout, "Response from `ForensicsAPI.GetBlastRadius`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetBlastRadiusRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hash** | **string** | BLAKE3 hash of the compromised artifact (prefixed, e.g. blake3:abc...) | 
 **from** | **time.Time** | Start of the time window (default 72 hours ago) | 
 **to** | **time.Time** | End of the time window (default now) | 

### Return type

[**BlastRadiusResponse**](BlastRadiusResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetForensicsProvenance

> ProvenanceResponse GetForensicsProvenance(ctx).Node(node).At(at).Execute()

Get point-in-time artifact stack for a node



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
	node := "node_example" // string | Node name to query
	at := time.Now() // time.Time | Point-in-time timestamp

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ForensicsAPI.GetForensicsProvenance(context.Background()).Node(node).At(at).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ForensicsAPI.GetForensicsProvenance``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetForensicsProvenance`: ProvenanceResponse
	fmt.Fprintf(os.Stdout, "Response from `ForensicsAPI.GetForensicsProvenance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetForensicsProvenanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **node** | **string** | Node name to query | 
 **at** | **time.Time** | Point-in-time timestamp | 

### Return type

[**ProvenanceResponse**](ProvenanceResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetForensicsTimeline

> TimelineResponse GetForensicsTimeline(ctx).Hash(hash).From(from).To(to).Node(node).Execute()

Get chronological event stream for a hash



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
	hash := "hash_example" // string | BLAKE3 hash to trace through the ledger
	from := time.Now() // time.Time | Start of the time window (default 72 hours ago) (optional)
	to := time.Now() // time.Time | End of the time window (default now) (optional)
	node := "node_example" // string | Filter events to a specific node (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ForensicsAPI.GetForensicsTimeline(context.Background()).Hash(hash).From(from).To(to).Node(node).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ForensicsAPI.GetForensicsTimeline``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetForensicsTimeline`: TimelineResponse
	fmt.Fprintf(os.Stdout, "Response from `ForensicsAPI.GetForensicsTimeline`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetForensicsTimelineRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hash** | **string** | BLAKE3 hash to trace through the ledger | 
 **from** | **time.Time** | Start of the time window (default 72 hours ago) | 
 **to** | **time.Time** | End of the time window (default now) | 
 **node** | **string** | Filter events to a specific node | 

### Return type

[**TimelineResponse**](TimelineResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RevokeHash

> RevokeResponse RevokeHash(ctx).RevokeRequest(revokeRequest).Execute()

Emergency revocation of a compromised hash



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
	revokeRequest := *openapiclient.NewRevokeRequest("blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "Reason_example", "Severity_example", "Operator_example") // RevokeRequest | 

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ForensicsAPI.RevokeHash(context.Background()).RevokeRequest(revokeRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ForensicsAPI.RevokeHash``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RevokeHash`: RevokeResponse
	fmt.Fprintf(os.Stdout, "Response from `ForensicsAPI.RevokeHash`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiRevokeHashRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **revokeRequest** | [**RevokeRequest**](RevokeRequest.md) |  | 

### Return type

[**RevokeResponse**](RevokeResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

