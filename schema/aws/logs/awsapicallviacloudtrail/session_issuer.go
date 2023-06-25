package awsapicallviacloudtrail

type SessionIssuer struct {
    AccountId string `json:"accountId"`
    PrincipalId string `json:"principalId"`
    SessionIssuerType string `json:"type"`
    Arn string `json:"arn"`
    UserName string `json:"userName"`
}

func (s *SessionIssuer) SetAccountId(accountId string) {
    s.AccountId = accountId
}

func (s *SessionIssuer) SetPrincipalId(principalId string) {
    s.PrincipalId = principalId
}

func (s *SessionIssuer) SetSessionIssuerType(sessionIssuerType string) {
    s.SessionIssuerType = sessionIssuerType
}

func (s *SessionIssuer) SetArn(arn string) {
    s.Arn = arn
}

func (s *SessionIssuer) SetUserName(userName string) {
    s.UserName = userName
}
