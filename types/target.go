package types

import (
	"fmt"
	"github.com/ryanjarv/sqs/schema/aws/logs/awsapicallviacloudtrail"
	"strings"
)

type InternalIdentity interface {
}

// Target returns a unique UserIdentity if a new session was created as a result of the current event.
//
// The returned UserIdentity object must contain the data necessary for matching events made with
// the newly created session back to this event.
//
// NOTE: Values in the identity struct can mean different things in different contexts. Interpretation of the fields is
// handled by the Id() method below.
//
func (e AssumeRoleEvent) Target() *UserIdentity {
	if e.ErrorCode != "" {
		return nil
	}

	id := &UserIdentity{}

	switch e.EventName {
	case "AssumeRole", "GetFederationToken", "ConsoleLogin":
		id = &UserIdentity{
			SessionContext: &awsapicallviacloudtrail.SessionContext{
				Attributes: awsapicallviacloudtrail.Attributes{CreationDate: e.EventTime},
			},
		}
	default:
		return nil
	}

	switch e.EventName {
	case "ConsoleLogin":
		//
		// The ARN issuer will stay the same when ConsoleLogin is called from a role. See the role-console-login.json
		// file for an example.
		//
		// This likely doesn't cover other cases of ConsoleLogin.
		//
		id.Arn = e.UserIdentity.SessionContext.SessionIssuer.Arn
	case "AssumeRole":
		//
		// TODO: Check sharedEventID
		//
		id.Type = "AssumedRole"
		id.Arn = e.ResponseElements.AssumedRoleUser.Arn
		id.AccessKeyId = e.ResponseElements.Credentials.AccessKeyId

		//
		// Skip cross-account assume role events for now if this event isn't from the source account. If the
		// target account event Identity happens to be returned first it causes subsequent sessions to have the
		// original identity of the source account rather than the source user in the source account.
		//
		// TODO: This breaks when we don't have access to the source account.
		//
		if e.UserIdentity.AccountId != e.RecipientAccountId {
			return nil
		}
	case "GetFederationToken":
		id.Type = "FederatedUser"
		id.Arn = e.ResponseElements.FederatedUser.Arn
		id.AccessKeyId = e.ResponseElements.Credentials.AccessKeyId
	}

	return id
}

// Id represents a unique UserIdentity context
func (i UserIdentity) Id() (id string) {
	// Remove the session name from the principal ID if it exists. It is user controlled, but mainly it can't be
	// referenced from the issuer context.
	resourceId := strings.Split(i.PrincipalId, ":")[0]

	switch i.Type {
	case "IAMUser":
		// IAMUser::123456789012:AIDAXXXXXXXXXXXXXXXXX:yourusername
		id = fmt.Sprintf("%s:%s:%s:%s:%s", i.Type, i.InvokedBy, i.AccountId, resourceId, i.UserName)
	case "AssumedRole":
		// AssumedRole::arn:aws:sts::123456789012:assumed-role/test2/XX:ASIAXXXXXXXXXXXXXXXX:1664688868
		id = fmt.Sprintf("%s:%s:%s:%s:%d", i.Type, i.InvokedBy, i.Arn, i.AccessKeyId, i.SessionContext.Attributes.CreationDate.Unix())

		//
		// TODO: Cover ConsoleLogin from assume-role source. This is difficult because we can only identify the
		//   resulting session based on the original session arn and the creation time, there is no access
		//   key in there response. We also can't identify if the source should be a ConsoleLogin call.
		//
	case "AWSAccount":
		// To actually reliably track sessions across accounts we need to use the sharedEventId.
		//
		// AWSAccount::123456789012:AIDAXXXXXXXXXXXXXXXXX
		id = fmt.Sprintf("%s:%s:%s", i.Type, i.AccountId, i.PrincipalId)
	case "AWSService":
		// Consolidate sessions that originate from AWS Services, they create too many unique sessions.
		//
		// AWSService:codepipeline.amazonaws.com
		id = fmt.Sprintf("%s:%s", i.Type, i.InvokedBy)
	case "FederatedUser":
		// TODO: Ensure Source can match this
		id = fmt.Sprintf("%s:%s:%s:%s:%d", i.Type, i.InvokedBy, i.Arn, i.AccessKeyId, i.SessionContext.Attributes.CreationDate.Unix())
	default:
		panic("unknown user identity type")
	}

	// AwsConsoleSignIn event type will not have a SessionContext
	// TODO: Tying this to the ID means we can't reference it from the session issuer object.
	//if i.SessionContext != nil {
	//	id = fmt.Sprintf("%s:%d", id, i.SessionContext.Attributes.CreationDate.Unix())
	//}

	//if arn == "" && !ec2PrincipalRe.MatchString(id.PrincipalId) {
	//	panic("investigate")
	//}
	return id
}
