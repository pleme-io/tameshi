# AkeylessSecretAttestation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**GatewayUrl** | **string** | URL of the Akeyless Gateway | 
**AuthMethod** | [**AkeylessAuthMethod**](AkeylessAuthMethod.md) |  | 
**SecretsAccessed** | [**[]AkeylessSecretAccess**](AkeylessSecretAccess.md) | List of secrets accessed during deployment | 
**GatewayCertificateHash** | **string** | BLAKE3 hash of the gateway TLS certificate | 
**SessionHash** | **string** | BLAKE3 hash of the authentication session | 

## Methods

### NewAkeylessSecretAttestation

`func NewAkeylessSecretAttestation(gatewayUrl string, authMethod AkeylessAuthMethod, secretsAccessed []AkeylessSecretAccess, gatewayCertificateHash string, sessionHash string, ) *AkeylessSecretAttestation`

NewAkeylessSecretAttestation instantiates a new AkeylessSecretAttestation object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAkeylessSecretAttestationWithDefaults

`func NewAkeylessSecretAttestationWithDefaults() *AkeylessSecretAttestation`

NewAkeylessSecretAttestationWithDefaults instantiates a new AkeylessSecretAttestation object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetGatewayUrl

`func (o *AkeylessSecretAttestation) GetGatewayUrl() string`

GetGatewayUrl returns the GatewayUrl field if non-nil, zero value otherwise.

### GetGatewayUrlOk

`func (o *AkeylessSecretAttestation) GetGatewayUrlOk() (*string, bool)`

GetGatewayUrlOk returns a tuple with the GatewayUrl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGatewayUrl

`func (o *AkeylessSecretAttestation) SetGatewayUrl(v string)`

SetGatewayUrl sets GatewayUrl field to given value.


### GetAuthMethod

`func (o *AkeylessSecretAttestation) GetAuthMethod() AkeylessAuthMethod`

GetAuthMethod returns the AuthMethod field if non-nil, zero value otherwise.

### GetAuthMethodOk

`func (o *AkeylessSecretAttestation) GetAuthMethodOk() (*AkeylessAuthMethod, bool)`

GetAuthMethodOk returns a tuple with the AuthMethod field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAuthMethod

`func (o *AkeylessSecretAttestation) SetAuthMethod(v AkeylessAuthMethod)`

SetAuthMethod sets AuthMethod field to given value.


### GetSecretsAccessed

`func (o *AkeylessSecretAttestation) GetSecretsAccessed() []AkeylessSecretAccess`

GetSecretsAccessed returns the SecretsAccessed field if non-nil, zero value otherwise.

### GetSecretsAccessedOk

`func (o *AkeylessSecretAttestation) GetSecretsAccessedOk() (*[]AkeylessSecretAccess, bool)`

GetSecretsAccessedOk returns a tuple with the SecretsAccessed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSecretsAccessed

`func (o *AkeylessSecretAttestation) SetSecretsAccessed(v []AkeylessSecretAccess)`

SetSecretsAccessed sets SecretsAccessed field to given value.


### GetGatewayCertificateHash

`func (o *AkeylessSecretAttestation) GetGatewayCertificateHash() string`

GetGatewayCertificateHash returns the GatewayCertificateHash field if non-nil, zero value otherwise.

### GetGatewayCertificateHashOk

`func (o *AkeylessSecretAttestation) GetGatewayCertificateHashOk() (*string, bool)`

GetGatewayCertificateHashOk returns a tuple with the GatewayCertificateHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGatewayCertificateHash

`func (o *AkeylessSecretAttestation) SetGatewayCertificateHash(v string)`

SetGatewayCertificateHash sets GatewayCertificateHash field to given value.


### GetSessionHash

`func (o *AkeylessSecretAttestation) GetSessionHash() string`

GetSessionHash returns the SessionHash field if non-nil, zero value otherwise.

### GetSessionHashOk

`func (o *AkeylessSecretAttestation) GetSessionHashOk() (*string, bool)`

GetSessionHashOk returns a tuple with the SessionHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSessionHash

`func (o *AkeylessSecretAttestation) SetSessionHash(v string)`

SetSessionHash sets SessionHash field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


