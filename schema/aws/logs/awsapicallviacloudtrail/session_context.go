package awsapicallviacloudtrail

type SessionContext struct {
    SessionIssuer SessionIssuer `json:"sessionIssuer"`
    Attributes Attributes `json:"attributes"`
}

func (s *SessionContext) SetSessionIssuer(sessionIssuer SessionIssuer) {
    s.SessionIssuer = sessionIssuer
}

func (s *SessionContext) SetAttributes(attributes Attributes) {
    s.Attributes = attributes
}
