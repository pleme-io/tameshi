# HealthApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**healthz**](HealthApi.md#healthz) | **GET** /healthz | Liveness probe |
| [**readyz**](HealthApi.md#readyz) | **GET** /readyz | Readiness probe |



## healthz

> healthz()

Liveness probe

Returns 200 when the service process is alive.

### Example

```ts
import {
  Configuration,
  HealthApi,
} from '@tameshi/client';
import type { HealthzRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new HealthApi();

  try {
    const data = await api.healthz();
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters

This endpoint does not need any parameter.

### Return type

`void` (Empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Service is alive |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## readyz

> readyz()

Readiness probe

Returns 200 when the service is ready to accept traffic, 503 otherwise.

### Example

```ts
import {
  Configuration,
  HealthApi,
} from '@tameshi/client';
import type { ReadyzRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new HealthApi();

  try {
    const data = await api.readyz();
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters

This endpoint does not need any parameter.

### Return type

`void` (Empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Service is ready |  -  |
| **503** | Service is not ready |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

