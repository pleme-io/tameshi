# GatesApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getGate**](GatesApi.md#getgate) | **GET** /api/v1/gates/{name} | Get a signature gate by name |
| [**listGates**](GatesApi.md#listgates) | **GET** /api/v1/gates | List all signature gates |
| [**verifyGate**](GatesApi.md#verifygate) | **GET** /api/v1/gates/{name}/verify | Verify a signature gate |



## getGate

> SignatureGate getGate(name)

Get a signature gate by name

Returns the full SignatureGate resource including spec and status.

### Example

```ts
import {
  Configuration,
  GatesApi,
} from '@tameshi/client';
import type { GetGateRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new GatesApi();

  const body = {
    // string | Name of the SignatureGate resource
    name: name_example,
  } satisfies GetGateRequest;

  try {
    const data = await api.getGate(body);
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
| **name** | `string` | Name of the SignatureGate resource | [Defaults to `undefined`] |

### Return type

[**SignatureGate**](SignatureGate.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | The requested signature gate |  -  |
| **404** | Gate not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## listGates

> Array&lt;GateSummary&gt; listGates()

List all signature gates

Returns a summary of every SignatureGate resource across all namespaces.

### Example

```ts
import {
  Configuration,
  GatesApi,
} from '@tameshi/client';
import type { ListGatesRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new GatesApi();

  try {
    const data = await api.listGates();
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

[**Array&lt;GateSummary&gt;**](GateSummary.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | List of gate summaries |  -  |
| **500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## verifyGate

> GateVerifyResult verifyGate(name)

Verify a signature gate

Triggers an immediate verification of the gate by recomputing each layer hash and comparing the composite signature against the expected value. 

### Example

```ts
import {
  Configuration,
  GatesApi,
} from '@tameshi/client';
import type { VerifyGateRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new GatesApi();

  const body = {
    // string | Name of the SignatureGate resource to verify
    name: name_example,
  } satisfies VerifyGateRequest;

  try {
    const data = await api.verifyGate(body);
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
| **name** | `string` | Name of the SignatureGate resource to verify | [Defaults to `undefined`] |

### Return type

[**GateVerifyResult**](GateVerifyResult.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Verification result |  -  |
| **404** | Gate not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

