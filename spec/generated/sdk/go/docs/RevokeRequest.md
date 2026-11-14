# RevokeRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Hash** | **string** | BLAKE3 hash in prefixed hex format | 
**Reason** | **string** | CVE identifier or reason for revocation (e.g. CVE-2026-XXXX) | 
**Severity** | **string** | Severity of the incident | 
**Operator** | **string** | Identity of the operator performing the revocation (e.g. email) | 

## Methods

### NewRevokeRequest

`func NewRevokeRequest(hash string, reason string, severity string, operator string, ) *RevokeRequest`

NewRevokeRequest instantiates a new RevokeRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewRevokeRequestWithDefaults

`func NewRevokeRequestWithDefaults() *RevokeRequest`

NewRevokeRequestWithDefaults instantiates a new RevokeRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetHash

`func (o *RevokeRequest) GetHash() string`

GetHash returns the Hash field if non-nil, zero value otherwise.

### GetHashOk

`func (o *RevokeRequest) GetHashOk() (*string, bool)`

GetHashOk returns a tuple with the Hash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHash

`func (o *RevokeRequest) SetHash(v string)`

SetHash sets Hash field to given value.


### GetReason

`func (o *RevokeRequest) GetReason() string`

GetReason returns the Reason field if non-nil, zero value otherwise.

### GetReasonOk

`func (o *RevokeRequest) GetReasonOk() (*string, bool)`

GetReasonOk returns a tuple with the Reason field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReason

`func (o *RevokeRequest) SetReason(v string)`

SetReason sets Reason field to given value.


### GetSeverity

`func (o *RevokeRequest) GetSeverity() string`

GetSeverity returns the Severity field if non-nil, zero value otherwise.

### GetSeverityOk

`func (o *RevokeRequest) GetSeverityOk() (*string, bool)`

GetSeverityOk returns a tuple with the Severity field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSeverity

`func (o *RevokeRequest) SetSeverity(v string)`

SetSeverity sets Severity field to given value.


### GetOperator

`func (o *RevokeRequest) GetOperator() string`

GetOperator returns the Operator field if non-nil, zero value otherwise.

### GetOperatorOk

`func (o *RevokeRequest) GetOperatorOk() (*string, bool)`

GetOperatorOk returns a tuple with the Operator field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOperator

`func (o *RevokeRequest) SetOperator(v string)`

SetOperator sets Operator field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


