# SecretAttestation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**GatewayUrl** | **string** | URL of the secrets-manager Gateway | 
**AuthMethod** | [**SecretAuthMethod**](SecretAuthMethod.md) |  | 
**SecretsAccessed** | [**[]SecretAccess**](SecretAccess.md) | List of secrets accessed during deployment | 
**GatewayCertificateHash** | **string** | BLAKE3 hash of the gateway TLS certificate | 
**SessionHash** | **string** | BLAKE3 hash of the authentication session | 

## Methods

### NewSecretAttestation

`func NewSecretAttestation(gatewayUrl string, authMethod SecretAuthMethod, secretsAccessed []SecretAccess, gatewayCertificateHash string, sessionHash string, ) *SecretAttestation`

NewSecretAttestation instantiates a new SecretAttestation object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSecretAttestationWithDefaults

`func NewSecretAttestationWithDefaults() *SecretAttestation`

NewSecretAttestationWithDefaults instantiates a new SecretAttestation object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetGatewayUrl

`func (o *SecretAttestation) GetGatewayUrl() string`

GetGatewayUrl returns the GatewayUrl field if non-nil, zero value otherwise.

### GetGatewayUrlOk

`func (o *SecretAttestation) GetGatewayUrlOk() (*string, bool)`

GetGatewayUrlOk returns a tuple with the GatewayUrl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGatewayUrl

`func (o *SecretAttestation) SetGatewayUrl(v string)`

SetGatewayUrl sets GatewayUrl field to given value.


### GetAuthMethod

`func (o *SecretAttestation) GetAuthMethod() SecretAuthMethod`

GetAuthMethod returns the AuthMethod field if non-nil, zero value otherwise.

### GetAuthMethodOk

`func (o *SecretAttestation) GetAuthMethodOk() (*SecretAuthMethod, bool)`

GetAuthMethodOk returns a tuple with the AuthMethod field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAuthMethod

`func (o *SecretAttestation) SetAuthMethod(v SecretAuthMethod)`

SetAuthMethod sets AuthMethod field to given value.


### GetSecretsAccessed

`func (o *SecretAttestation) GetSecretsAccessed() []SecretAccess`

GetSecretsAccessed returns the SecretsAccessed field if non-nil, zero value otherwise.

### GetSecretsAccessedOk

`func (o *SecretAttestation) GetSecretsAccessedOk() (*[]SecretAccess, bool)`

GetSecretsAccessedOk returns a tuple with the SecretsAccessed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSecretsAccessed

`func (o *SecretAttestation) SetSecretsAccessed(v []SecretAccess)`

SetSecretsAccessed sets SecretsAccessed field to given value.


### GetGatewayCertificateHash

`func (o *SecretAttestation) GetGatewayCertificateHash() string`

GetGatewayCertificateHash returns the GatewayCertificateHash field if non-nil, zero value otherwise.

### GetGatewayCertificateHashOk

`func (o *SecretAttestation) GetGatewayCertificateHashOk() (*string, bool)`

GetGatewayCertificateHashOk returns a tuple with the GatewayCertificateHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGatewayCertificateHash

`func (o *SecretAttestation) SetGatewayCertificateHash(v string)`

SetGatewayCertificateHash sets GatewayCertificateHash field to given value.


### GetSessionHash

`func (o *SecretAttestation) GetSessionHash() string`

GetSessionHash returns the SessionHash field if non-nil, zero value otherwise.

### GetSessionHashOk

`func (o *SecretAttestation) GetSessionHashOk() (*string, bool)`

GetSessionHashOk returns a tuple with the SessionHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSessionHash

`func (o *SecretAttestation) SetSessionHash(v string)`

SetSessionHash sets SessionHash field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


