package types

import (
	"encoding/json"
	"github.com/ryanjarv/goutil/utils"
	"github.com/ryanjarv/sqs/schema/aws/logs/awsapicallviacloudtrail"
	"hash/maphash"
	"regexp"
	"time"
)

var ec2PrincipalRe = regexp.MustCompile(`^AROA[A-Z\d]{17}:i-[\da-z]{17}$`)

var hash = maphash.Hash{}

// UserIdentity
//
// This will exist on all events, how it's used varies however depending on the context.
//
// More info: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
//
type UserIdentity struct {
	// Type can be:
	//
	//  Same Account
	//    Persistent Access
	//      * Root
	//        * The request was made with your AWS account credentials. If the userIdentity type is Root and you set an
	//          alias for your account, the userName field contains your account alias.
	//      * IAMUser
	//        * The request was made with the credentials of an IAM user.
	//      * Role
	//        * The request was made with a persistent IAM identity that has specific permissions. The issuer of role
	//          sessions is always the role.
	//
	//    Session Based Access
	//      * AssumedRole
	//        * The request was made with temporary security credentials that were obtained with a role by making a call
	//          to the AWS Security Token Service (AWS STS) AssumeRole API. This can include roles for Amazon EC2 and
	//          cross-account API access.
	//      * FederatedUser
	//        * The request was made with temporary security credentials that were obtained via a call to the AWS STS
	//          GetFederationToken API.
	//
	//
	//  Cross-Account Access
	//
	//     AWSAccount and AWSService appear for type in your logs when there is cross-account access using an IAM role
	//     that you own.
	//
	//     * AWSAccount
	//       * The request was made by another AWS account.
	//     * AWSService
	//       * The request was made by an AWS account that belongs to an AWS service.
	//
	//
	//  Other
	//      * Directory
	//        * The request was made to a directory service, and the type is unknown. Directory services include the
	//          following: Amazon WorkDocs and Amazon QuickSight.
	//      * Unknown
	//        * The request was made with an identity type that CloudTrail cannot determine.
	//
	//
	//  Undocumented types:
	//    * SAMLUser
	//    * WebIdentityUser
	//    * WebIdentityUser
	//    * null
	//      * Appears to only occur on `AwsServiceEvent` event types.
	//
	Type string `json:"type,omitempty"`

	InvokedBy string `json:"invokedBy,omitempty"`

	// PrincipalId
	// A unique identifier for the entity that made the call. For requests made with temporary security credentials,
	// this value includes the session name that is passed to the AssumeRole, AssumeRoleWithWebIdentity, or
	// GetFederationToken API call.
	//
	//   Optional: True
	//
	// Terms from https://docs.aws.amazon.com/IAM/latest/UserGuide/intro-structure.html#intro-structure-terms
	// 	 * IAM Entities
	//	   * An entity is the IAM resource objects that AWS uses for authentication. These include IAM users and roles.
	//
	//   * Principals
	//     * A person or application that uses the AWS account root user, an IAM user, or an IAM role to sign in and
	//       make requests to AWS. Principals include federated users and assumed roles.
	//
	// Examples:
	//   AROAXXXXXXXXXXXXXXXXX:XX
	//   IAMUser: AIDAXXXXXXXXXXXXXXXXX
	//   AWSService: null
	PrincipalId string `json:"principalId,omitempty"`

	// The Amazon Resource Name (ARN) of the principal that made the call. The last section of the arn contains the
	// user or role that made the call.
	//
	// Optional: True
	//
	Arn string `json:"arn,omitempty"`

	UserName string `json:"UserName,omitempty"`

	// AccountId      The account that owns the entity that was used to get credentials.
	AccountId      string                                  `json:"accountId,omitempty"`
	AccessKeyId    string                                  `json:"accessKeyId,omitempty"`
	SessionContext *awsapicallviacloudtrail.SessionContext `json:"sessionContext,omitempty"`
}

func (i UserIdentity) Group() string {
	return i.AccountId
}

func (i UserIdentity) Persistent() bool {
	return utils.In([]string{"Root", "IAMUser", "Role"}, i.Type)
}

func (i UserIdentity) CrossAccount() bool {
	return utils.In([]string{"AWSAccount", "AWSService"}, i.Type)
}

type RequestParameters struct {
	RoleArn         string `json:"roleArn,omitempty"`
	RoleSessionName string `json:"roleSessionName,omitempty"`
	ExternalId      string `json:"externalId,omitempty"`
	DurationSeconds int    `json:"durationSeconds,omitempty"`

	// Policy contains the scoped down IAM policy provided in the request if it is present.
	// We don't care about it for now so defer processing of this section.
	Policy *json.RawMessage `json:"policy,omitempty"`

	// Name appears on:
	//  * sts:GetFederationToken
	//     * User controllable.
	//     * Can only be called by IAM Users
	Name string
}
type Credentials struct {
	AccessKeyId  string `json:"accessKeyId,omitempty"`
	SessionToken string `json:"sessionToken,omitempty"`
	Expiration   string `json:"expiration,omitempty"`
}

type FederatedUser struct {
	FederatedUserId string `json:"federatedUserId"`
	Arn             string `json:"arn"`
}
type AssumeRoleUser struct {
	AssumedRoleId string `json:"assumedRoleId,omitempty"`
	Arn           string `json:"arn,omitempty"`
}

type ResponseElements struct {
	Credentials     *Credentials    `json:"credentials,omitempty"`
	AssumedRoleUser *AssumeRoleUser `json:"assumedRoleUser,omitempty"`
	FederatedUser   *FederatedUser  `json:"federatedUser,omitempty"`

	// PackedPolicySize is only present when a policy as sent in the request.
	PackedPolicySize *int `json:"packedPolicySize,omitempty"`
}

type AssumeRoleEvent struct {
	EventVersion      string            `json:"eventVersion,omitempty"`
	UserIdentity      UserIdentity      `json:"userIdentity,omitempty"`
	EventTime         time.Time         `json:"eventTime,omitempty"`
	EventSource       string            `json:"eventSource,omitempty"`
	EventName         string            `json:"eventName,omitempty"`
	AwsRegion         string            `json:"awsRegion,omitempty"`
	SourceIPAddress   string            `json:"sourceIPAddress,omitempty"`
	UserAgent         string            `json:"userAgent,omitempty"`
	RequestParameters RequestParameters `json:"requestParameters,omitempty"`
	ResponseElements  ResponseElements  `json:"responseElements,omitempty"`
	ErrorCode         string            `json:"errorCode,omitempty"`
	ErrorMessage      string            `json:"errorMessage,omitempty"`
	RequestID         string            `json:"requestID,omitempty"`
	EventID           string            `json:"eventID,omitempty"`
	ReadOnly          bool              `json:"readOnly,omitempty"`
	Resources         []struct {
		AccountId string `json:"accountId,omitempty"`
		Type      string `json:"type,omitempty"`
		ARN       string `json:"ARN,omitempty"`
	} `json:"resources,omitempty"`

	// EventType can be:
	//   * AwsApiCall
	//   * AwsConsoleSignIn
	//     * Attempts to sign in to the AWS Management Console, the AWS Discussion Forums, and the AWS Support Center.
	//     * https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html
	//   * AwsServiceEvent
	//     * These events are created by AWS services but are not directly triggered by a request to a public AWS API.
	//     * https://docs.aws.amazon.com/awscloudtrail/latest/userguide/non-api-aws-service-events.html
	EventType string `json:"eventType,omitempty"`

	ManagementEvent    bool   `json:"managementEvent,omitempty"`
	RecipientAccountId string `json:"recipientAccountId,omitempty"`
	SharedEventID      string `json:"sharedEventID,omitempty"`
	EventCategory      string `json:"eventCategory,omitempty"`
	TlsDetails         struct {
		TlsVersion               string `json:"tlsVersion,omitempty"`
		CipherSuite              string `json:"cipherSuite,omitempty"`
		ClientProvidedHostHeader string `json:"clientProvidedHostHeader,omitempty"`
	} `json:"tlsDetails,omitempty"`
}

func (e AssumeRoleEvent) Id() string {
	return e.EventID
}

func (e AssumeRoleEvent) Group() string {
	return e.EventType
}

//func (e AssumeRoleEvent) SourceIdentity() *SessionContext {
//	sess.Principal = e.UserIdentity.Principal()
//	sess.AccessKeyID = e.UserIdentity.AccessKeyId
//
//	//if e.BaseUserIdentity
//	//sess.EventTime = &e.BaseUserIdentity.SessionContext.
//
//	return sess
//}
//
//func (e AssumeRoleEvent) TargetIdentity() (sess Session) {
//	sess.EventTime = &e.EventTime
//	if e.UserIdentity.SessionContext != nil {
//		// SessionContext creation date on the target should match the time the source identity command was ran.
//		sess.EventTime = e.UserIdentity.SessionContext.Attributes.CreationDate
//	}
//
//	sess.AccessKeyID = e.ResponseElements.Credentials.AccessKeyId
//	sess.Principal = e.RequestParameters.RoleArn
//
//	return sess
//}

//type Session struct {
//	EventTime   *time.Time
//	AccessKeyID string
//	Principal   string
//}
//
//func (s Session) Id() string {
//	id, err := json.Marshal(s)
//	if err != nil {
//		panic(err)
//	}
//	return string(id)
//}
//
//func (s Session) Name() string {
//	return fmt.Sprintf("%s (%s)", s.AccessKeyID, s.Principal)
//}
//
//func (s Session) Group() string {
//	return s.Principal
//}
//
