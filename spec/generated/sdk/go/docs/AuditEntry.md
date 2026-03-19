# AuditEntry

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Timestamp** | **time.Time** | When the audit event occurred | 
**Action** | [**AuditAction**](AuditAction.md) |  | 
**Signature** | **string** | Signature associated with this audit event | 
**Details** | Pointer to **NullableString** | Human-readable details about the event | [optional] 
**Resource** | Pointer to **NullableString** | Kubernetes resource involved (e.g. apps/v1/Deployment/my-app) | [optional] 
**Allowed** | Pointer to **NullableBool** | Whether the operation was allowed (for admission events) | [optional] 

## Methods

### NewAuditEntry

`func NewAuditEntry(timestamp time.Time, action AuditAction, signature string, ) *AuditEntry`

NewAuditEntry instantiates a new AuditEntry object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAuditEntryWithDefaults

`func NewAuditEntryWithDefaults() *AuditEntry`

NewAuditEntryWithDefaults instantiates a new AuditEntry object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTimestamp

`func (o *AuditEntry) GetTimestamp() time.Time`

GetTimestamp returns the Timestamp field if non-nil, zero value otherwise.

### GetTimestampOk

`func (o *AuditEntry) GetTimestampOk() (*time.Time, bool)`

GetTimestampOk returns a tuple with the Timestamp field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTimestamp

`func (o *AuditEntry) SetTimestamp(v time.Time)`

SetTimestamp sets Timestamp field to given value.


### GetAction

`func (o *AuditEntry) GetAction() AuditAction`

GetAction returns the Action field if non-nil, zero value otherwise.

### GetActionOk

`func (o *AuditEntry) GetActionOk() (*AuditAction, bool)`

GetActionOk returns a tuple with the Action field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAction

`func (o *AuditEntry) SetAction(v AuditAction)`

SetAction sets Action field to given value.


### GetSignature

`func (o *AuditEntry) GetSignature() string`

GetSignature returns the Signature field if non-nil, zero value otherwise.

### GetSignatureOk

`func (o *AuditEntry) GetSignatureOk() (*string, bool)`

GetSignatureOk returns a tuple with the Signature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignature

`func (o *AuditEntry) SetSignature(v string)`

SetSignature sets Signature field to given value.


### GetDetails

`func (o *AuditEntry) GetDetails() string`

GetDetails returns the Details field if non-nil, zero value otherwise.

### GetDetailsOk

`func (o *AuditEntry) GetDetailsOk() (*string, bool)`

GetDetailsOk returns a tuple with the Details field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDetails

`func (o *AuditEntry) SetDetails(v string)`

SetDetails sets Details field to given value.

### HasDetails

`func (o *AuditEntry) HasDetails() bool`

HasDetails returns a boolean if a field has been set.

### SetDetailsNil

`func (o *AuditEntry) SetDetailsNil(b bool)`

 SetDetailsNil sets the value for Details to be an explicit nil

### UnsetDetails
`func (o *AuditEntry) UnsetDetails()`

UnsetDetails ensures that no value is present for Details, not even an explicit nil
### GetResource

`func (o *AuditEntry) GetResource() string`

GetResource returns the Resource field if non-nil, zero value otherwise.

### GetResourceOk

`func (o *AuditEntry) GetResourceOk() (*string, bool)`

GetResourceOk returns a tuple with the Resource field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetResource

`func (o *AuditEntry) SetResource(v string)`

SetResource sets Resource field to given value.

### HasResource

`func (o *AuditEntry) HasResource() bool`

HasResource returns a boolean if a field has been set.

### SetResourceNil

`func (o *AuditEntry) SetResourceNil(b bool)`

 SetResourceNil sets the value for Resource to be an explicit nil

### UnsetResource
`func (o *AuditEntry) UnsetResource()`

UnsetResource ensures that no value is present for Resource, not even an explicit nil
### GetAllowed

`func (o *AuditEntry) GetAllowed() bool`

GetAllowed returns the Allowed field if non-nil, zero value otherwise.

### GetAllowedOk

`func (o *AuditEntry) GetAllowedOk() (*bool, bool)`

GetAllowedOk returns a tuple with the Allowed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAllowed

`func (o *AuditEntry) SetAllowed(v bool)`

SetAllowed sets Allowed field to given value.

### HasAllowed

`func (o *AuditEntry) HasAllowed() bool`

HasAllowed returns a boolean if a field has been set.

### SetAllowedNil

`func (o *AuditEntry) SetAllowedNil(b bool)`

 SetAllowedNil sets the value for Allowed to be an explicit nil

### UnsetAllowed
`func (o *AuditEntry) UnsetAllowed()`

UnsetAllowed ensures that no value is present for Allowed, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


