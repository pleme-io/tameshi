# BlastRadiusResponseTimeRange

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**FirstSeen** | **time.Time** | Earliest timestamp the hash was observed in the ledger | 
**LastSeen** | **time.Time** | Most recent timestamp the hash was observed in the ledger | 

## Methods

### NewBlastRadiusResponseTimeRange

`func NewBlastRadiusResponseTimeRange(firstSeen time.Time, lastSeen time.Time, ) *BlastRadiusResponseTimeRange`

NewBlastRadiusResponseTimeRange instantiates a new BlastRadiusResponseTimeRange object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBlastRadiusResponseTimeRangeWithDefaults

`func NewBlastRadiusResponseTimeRangeWithDefaults() *BlastRadiusResponseTimeRange`

NewBlastRadiusResponseTimeRangeWithDefaults instantiates a new BlastRadiusResponseTimeRange object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetFirstSeen

`func (o *BlastRadiusResponseTimeRange) GetFirstSeen() time.Time`

GetFirstSeen returns the FirstSeen field if non-nil, zero value otherwise.

### GetFirstSeenOk

`func (o *BlastRadiusResponseTimeRange) GetFirstSeenOk() (*time.Time, bool)`

GetFirstSeenOk returns a tuple with the FirstSeen field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFirstSeen

`func (o *BlastRadiusResponseTimeRange) SetFirstSeen(v time.Time)`

SetFirstSeen sets FirstSeen field to given value.


### GetLastSeen

`func (o *BlastRadiusResponseTimeRange) GetLastSeen() time.Time`

GetLastSeen returns the LastSeen field if non-nil, zero value otherwise.

### GetLastSeenOk

`func (o *BlastRadiusResponseTimeRange) GetLastSeenOk() (*time.Time, bool)`

GetLastSeenOk returns a tuple with the LastSeen field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastSeen

`func (o *BlastRadiusResponseTimeRange) SetLastSeen(v time.Time)`

SetLastSeen sets LastSeen field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


