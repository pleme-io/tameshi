# GatesApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getGate**](GatesApi.md#getGate) | **GET** /api/v1/gates/{name} | Get a signature gate by name |
| [**listGates**](GatesApi.md#listGates) | **GET** /api/v1/gates | List all signature gates |
| [**verifyGate**](GatesApi.md#verifyGate) | **GET** /api/v1/gates/{name}/verify | Verify a signature gate |


<a name="getGate"></a>
# **getGate**
> SignatureGate getGate(name)

Get a signature gate by name

    Returns the full SignatureGate resource including spec and status.

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **name** | **String**| Name of the SignatureGate resource | [default to null] |

### Return type

[**SignatureGate**](../Models/SignatureGate.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="listGates"></a>
# **listGates**
> List listGates()

List all signature gates

    Returns a summary of every SignatureGate resource across all namespaces.

### Parameters
This endpoint does not need any parameter.

### Return type

[**List**](../Models/GateSummary.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="verifyGate"></a>
# **verifyGate**
> GateVerifyResult verifyGate(name)

Verify a signature gate

    Triggers an immediate verification of the gate by recomputing each layer hash and comparing the composite signature against the expected value. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **name** | **String**| Name of the SignatureGate resource to verify | [default to null] |

### Return type

[**GateVerifyResult**](../Models/GateVerifyResult.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

