package awsapicallviacloudtrail

import (
    "time"
)


type Attributes struct {
    MfaAuthenticated string `json:"mfaAuthenticated"`
    CreationDate time.Time `json:"creationDate"`
}

func (a *Attributes) SetMfaAuthenticated(mfaAuthenticated string) {
    a.MfaAuthenticated = mfaAuthenticated
}

func (a *Attributes) SetCreationDate(creationDate time.Time) {
    a.CreationDate = creationDate
}
