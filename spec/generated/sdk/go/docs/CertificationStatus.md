# CertificationStatus

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Phase** | [**CertPhase**](CertPhase.md) |  | 
**MasterSignature** | Pointer to **NullableString** | Composite master signature across all gates | [optional] 
**ComplianceSignature** | Pointer to **NullableString** | BLAKE3 hash of the compliance assessment result | [optional] 
**SecureSignature** | Pointer to **NullableString** | BLAKE3 hash combining master and compliance signatures | [optional] 
**LastCertifiedAt** | Pointer to **NullableTime** | Timestamp of the last successful certification | [optional] 
**GateStatuses** | Pointer to [**[]GateStatusRef**](GateStatusRef.md) | Status of each gate included in this certification | [optional] 
**AuditTrail** | Pointer to [**[]AuditEntry**](AuditEntry.md) | Ordered audit trail for this certification | [optional] 

## Methods

### NewCertificationStatus

`func NewCertificationStatus(phase CertPhase, ) *CertificationStatus`

NewCertificationStatus instantiates a new CertificationStatus object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCertificationStatusWithDefaults

`func NewCertificationStatusWithDefaults() *CertificationStatus`

NewCertificationStatusWithDefaults instantiates a new CertificationStatus object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetPhase

`func (o *CertificationStatus) GetPhase() CertPhase`

GetPhase returns the Phase field if non-nil, zero value otherwise.

### GetPhaseOk

`func (o *CertificationStatus) GetPhaseOk() (*CertPhase, bool)`

GetPhaseOk returns a tuple with the Phase field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPhase

`func (o *CertificationStatus) SetPhase(v CertPhase)`

SetPhase sets Phase field to given value.


### GetMasterSignature

`func (o *CertificationStatus) GetMasterSignature() string`

GetMasterSignature returns the MasterSignature field if non-nil, zero value otherwise.

### GetMasterSignatureOk

`func (o *CertificationStatus) GetMasterSignatureOk() (*string, bool)`

GetMasterSignatureOk returns a tuple with the MasterSignature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMasterSignature

`func (o *CertificationStatus) SetMasterSignature(v string)`

SetMasterSignature sets MasterSignature field to given value.

### HasMasterSignature

`func (o *CertificationStatus) HasMasterSignature() bool`

HasMasterSignature returns a boolean if a field has been set.

### SetMasterSignatureNil

`func (o *CertificationStatus) SetMasterSignatureNil(b bool)`

 SetMasterSignatureNil sets the value for MasterSignature to be an explicit nil

### UnsetMasterSignature
`func (o *CertificationStatus) UnsetMasterSignature()`

UnsetMasterSignature ensures that no value is present for MasterSignature, not even an explicit nil
### GetComplianceSignature

`func (o *CertificationStatus) GetComplianceSignature() string`

GetComplianceSignature returns the ComplianceSignature field if non-nil, zero value otherwise.

### GetComplianceSignatureOk

`func (o *CertificationStatus) GetComplianceSignatureOk() (*string, bool)`

GetComplianceSignatureOk returns a tuple with the ComplianceSignature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComplianceSignature

`func (o *CertificationStatus) SetComplianceSignature(v string)`

SetComplianceSignature sets ComplianceSignature field to given value.

### HasComplianceSignature

`func (o *CertificationStatus) HasComplianceSignature() bool`

HasComplianceSignature returns a boolean if a field has been set.

### SetComplianceSignatureNil

`func (o *CertificationStatus) SetComplianceSignatureNil(b bool)`

 SetComplianceSignatureNil sets the value for ComplianceSignature to be an explicit nil

### UnsetComplianceSignature
`func (o *CertificationStatus) UnsetComplianceSignature()`

UnsetComplianceSignature ensures that no value is present for ComplianceSignature, not even an explicit nil
### GetSecureSignature

`func (o *CertificationStatus) GetSecureSignature() string`

GetSecureSignature returns the SecureSignature field if non-nil, zero value otherwise.

### GetSecureSignatureOk

`func (o *CertificationStatus) GetSecureSignatureOk() (*string, bool)`

GetSecureSignatureOk returns a tuple with the SecureSignature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSecureSignature

`func (o *CertificationStatus) SetSecureSignature(v string)`

SetSecureSignature sets SecureSignature field to given value.

### HasSecureSignature

`func (o *CertificationStatus) HasSecureSignature() bool`

HasSecureSignature returns a boolean if a field has been set.

### SetSecureSignatureNil

`func (o *CertificationStatus) SetSecureSignatureNil(b bool)`

 SetSecureSignatureNil sets the value for SecureSignature to be an explicit nil

### UnsetSecureSignature
`func (o *CertificationStatus) UnsetSecureSignature()`

UnsetSecureSignature ensures that no value is present for SecureSignature, not even an explicit nil
### GetLastCertifiedAt

`func (o *CertificationStatus) GetLastCertifiedAt() time.Time`

GetLastCertifiedAt returns the LastCertifiedAt field if non-nil, zero value otherwise.

### GetLastCertifiedAtOk

`func (o *CertificationStatus) GetLastCertifiedAtOk() (*time.Time, bool)`

GetLastCertifiedAtOk returns a tuple with the LastCertifiedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastCertifiedAt

`func (o *CertificationStatus) SetLastCertifiedAt(v time.Time)`

SetLastCertifiedAt sets LastCertifiedAt field to given value.

### HasLastCertifiedAt

`func (o *CertificationStatus) HasLastCertifiedAt() bool`

HasLastCertifiedAt returns a boolean if a field has been set.

### SetLastCertifiedAtNil

`func (o *CertificationStatus) SetLastCertifiedAtNil(b bool)`

 SetLastCertifiedAtNil sets the value for LastCertifiedAt to be an explicit nil

### UnsetLastCertifiedAt
`func (o *CertificationStatus) UnsetLastCertifiedAt()`

UnsetLastCertifiedAt ensures that no value is present for LastCertifiedAt, not even an explicit nil
### GetGateStatuses

`func (o *CertificationStatus) GetGateStatuses() []GateStatusRef`

GetGateStatuses returns the GateStatuses field if non-nil, zero value otherwise.

### GetGateStatusesOk

`func (o *CertificationStatus) GetGateStatusesOk() (*[]GateStatusRef, bool)`

GetGateStatusesOk returns a tuple with the GateStatuses field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGateStatuses

`func (o *CertificationStatus) SetGateStatuses(v []GateStatusRef)`

SetGateStatuses sets GateStatuses field to given value.

### HasGateStatuses

`func (o *CertificationStatus) HasGateStatuses() bool`

HasGateStatuses returns a boolean if a field has been set.

### GetAuditTrail

`func (o *CertificationStatus) GetAuditTrail() []AuditEntry`

GetAuditTrail returns the AuditTrail field if non-nil, zero value otherwise.

### GetAuditTrailOk

`func (o *CertificationStatus) GetAuditTrailOk() (*[]AuditEntry, bool)`

GetAuditTrailOk returns a tuple with the AuditTrail field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAuditTrail

`func (o *CertificationStatus) SetAuditTrail(v []AuditEntry)`

SetAuditTrail sets AuditTrail field to given value.

### HasAuditTrail

`func (o *CertificationStatus) HasAuditTrail() bool`

HasAuditTrail returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


