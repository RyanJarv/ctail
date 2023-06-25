package awsapicallviacloudtrail

type UserIdentity struct {
    SessionContext SessionContext `json:"sessionContext"`
    AccessKeyId string `json:"accessKeyId"`
    AccountId string `json:"accountId"`
    PrincipalId string `json:"principalId"`
    UserIdentityType string `json:"type"`
    Arn string `json:"arn"`
    InvokedBy string `json:"invokedBy,omitempty"`
}

func (u *UserIdentity) SetSessionContext(sessionContext SessionContext) {
    u.SessionContext = sessionContext
}

func (u *UserIdentity) SetAccessKeyId(accessKeyId string) {
    u.AccessKeyId = accessKeyId
}

func (u *UserIdentity) SetAccountId(accountId string) {
    u.AccountId = accountId
}

func (u *UserIdentity) SetPrincipalId(principalId string) {
    u.PrincipalId = principalId
}

func (u *UserIdentity) SetUserIdentityType(userIdentityType string) {
    u.UserIdentityType = userIdentityType
}

func (u *UserIdentity) SetArn(arn string) {
    u.Arn = arn
}

func (u *UserIdentity) SetInvokedBy(invokedBy string) {
    u.InvokedBy = invokedBy
}
