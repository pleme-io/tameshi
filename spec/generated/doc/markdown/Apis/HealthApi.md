# HealthApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**healthz**](HealthApi.md#healthz) | **GET** /healthz | Liveness probe |
| [**readyz**](HealthApi.md#readyz) | **GET** /readyz | Readiness probe |


<a name="healthz"></a>
# **healthz**
> healthz()

Liveness probe

    Returns 200 when the service process is alive.

### Parameters
This endpoint does not need any parameter.

### Return type

null (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

<a name="readyz"></a>
# **readyz**
> readyz()

Readiness probe

    Returns 200 when the service is ready to accept traffic, 503 otherwise.

### Parameters
This endpoint does not need any parameter.

### Return type

null (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

