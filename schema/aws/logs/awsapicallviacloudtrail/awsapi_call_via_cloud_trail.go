package awsapicallviacloudtrail

import (
    "time"
)


type AWSAPICallViaCloudTrail struct {
    RequestParameters RequestParameters `json:"requestParameters"`
    UserIdentity UserIdentity `json:"userIdentity"`
    EventID string `json:"eventID"`
    AwsRegion string `json:"awsRegion"`
    EventVersion string `json:"eventVersion"`
    ResponseElements interface{} `json:"responseElements"`
    SourceIPAddress string `json:"sourceIPAddress"`
    EventSource string `json:"eventSource"`
    ErrorMessage string `json:"errorMessage,omitempty"`
    ErrorCode string `json:"errorCode,omitempty"`
    UserAgent string `json:"userAgent"`
    EventType string `json:"eventType"`
    ApiVersion string `json:"apiVersion,omitempty"`
    RequestID string `json:"requestID"`
    EventTime time.Time `json:"eventTime"`
    EventName string `json:"eventName"`
}

func (a *AWSAPICallViaCloudTrail) SetRequestParameters(requestParameters RequestParameters) {
    a.RequestParameters = requestParameters
}

func (a *AWSAPICallViaCloudTrail) SetUserIdentity(userIdentity UserIdentity) {
    a.UserIdentity = userIdentity
}

func (a *AWSAPICallViaCloudTrail) SetEventID(eventID string) {
    a.EventID = eventID
}

func (a *AWSAPICallViaCloudTrail) SetAwsRegion(awsRegion string) {
    a.AwsRegion = awsRegion
}

func (a *AWSAPICallViaCloudTrail) SetEventVersion(eventVersion string) {
    a.EventVersion = eventVersion
}

func (a *AWSAPICallViaCloudTrail) SetResponseElements(responseElements interface{}) {
    a.ResponseElements = responseElements
}

func (a *AWSAPICallViaCloudTrail) SetSourceIPAddress(sourceIPAddress string) {
    a.SourceIPAddress = sourceIPAddress
}

func (a *AWSAPICallViaCloudTrail) SetEventSource(eventSource string) {
    a.EventSource = eventSource
}

func (a *AWSAPICallViaCloudTrail) SetErrorMessage(errorMessage string) {
    a.ErrorMessage = errorMessage
}

func (a *AWSAPICallViaCloudTrail) SetErrorCode(errorCode string) {
    a.ErrorCode = errorCode
}

func (a *AWSAPICallViaCloudTrail) SetUserAgent(userAgent string) {
    a.UserAgent = userAgent
}

func (a *AWSAPICallViaCloudTrail) SetEventType(eventType string) {
    a.EventType = eventType
}

func (a *AWSAPICallViaCloudTrail) SetApiVersion(apiVersion string) {
    a.ApiVersion = apiVersion
}

func (a *AWSAPICallViaCloudTrail) SetRequestID(requestID string) {
    a.RequestID = requestID
}

func (a *AWSAPICallViaCloudTrail) SetEventTime(eventTime time.Time) {
    a.EventTime = eventTime
}

func (a *AWSAPICallViaCloudTrail) SetEventName(eventName string) {
    a.EventName = eventName
}
