# CertificationsApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getCertification**](CertificationsApi.md#getcertification) | **GET** /api/v1/certifications/{name} | Get certification by name |
| [**listCertifications**](CertificationsApi.md#listcertifications) | **GET** /api/v1/certifications | List all certifications |



## getCertification

> Certification getCertification(name)

Get certification by name

Returns the full Certification resource including spec and status.

### Example

```ts
import {
  Configuration,
  CertificationsApi,
} from '@tameshi/client';
import type { GetCertificationRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new CertificationsApi();

  const body = {
    // string | Name of the Certification resource
    name: name_example,
  } satisfies GetCertificationRequest;

  try {
    const data = await api.getCertification(body);
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
| **name** | `string` | Name of the Certification resource | [Defaults to `undefined`] |

### Return type

[**Certification**](Certification.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | The requested certification |  -  |
| **404** | Certification not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## listCertifications

> Array&lt;CertificationSummary&gt; listCertifications()

List all certifications

Returns a summary of every Certification resource across all namespaces.

### Example

```ts
import {
  Configuration,
  CertificationsApi,
} from '@tameshi/client';
import type { ListCertificationsRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new CertificationsApi();

  try {
    const data = await api.listCertifications();
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

[**Array&lt;CertificationSummary&gt;**](CertificationSummary.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | List of certification summaries |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

