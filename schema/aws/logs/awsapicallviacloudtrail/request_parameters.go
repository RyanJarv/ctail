package awsapicallviacloudtrail

type RequestParameters struct {
    LogGroupName string `json:"logGroupName"`
    LogStreamName string `json:"logStreamName,omitempty"`
}

func (r *RequestParameters) SetLogGroupName(logGroupName string) {
    r.LogGroupName = logGroupName
}

func (r *RequestParameters) SetLogStreamName(logStreamName string) {
    r.LogStreamName = logStreamName
}
