# ctail


This project doesn't work currently, it was moved out of another repo without being tested. I'm mainly publishing it because it has
some notes and code that I wanted to keep around.

## Quick Overview

The goal of the project was to have a command line utility for viewing enriched cloudtrail sessions live. So essentially you can
start the command, it will start trailing live events from cloudtrail, and the output will be normalized based on associated sessions.

In theory you could start with a given identity, get output limited to their current sessions and any future sessions (assume role, get session token, etc),
proxied sessions (web console), sessions across access key collisions, or whatever other wierd stuff aws does with cloudtrail logs...

But again this doesn't really work, I'm just keeping the notes here now...

## TODO


* Handle out of order cross-account assume role calls
  * CloudTrail doesn't gurantee event order, so a call using a session can come before the call to create the session itself
  * The source and target events happen the same second, they can't be sorted on date.
  * Maybe just need to have fall back ids?
* Handle representing collisions in the outputted JSON.
  * It is possible for two different sessions to have all the same identifying attributes we use to differentiate sessions.
    This happens primarily because access key id get's recycled occasionally and AWS doesn't output session tokens to the logs.
    See [hunters-research-is-aws-recycling-your-access-key](https://www.hunters.security/en/blog/hunters-research-is-aws-recycling-your-access-key)
    for more info.
  * This kinda sucks.. but should be able to handle this case. For example to matter to us the collision has to be:
    1) Two sessions from the same source principal, otherwise we can tell them apart.
    2) Has to happen the same second, otherwise we can tell them apart (based on .userIdentity.sessionContext.attributes.creationDate).
    3) some other stuff maybe? i don't remember now..
  * In any case, the result will be (in the context of this tool) that we know there is a collision and events by the same session that happen after
    can be one of two principals from the same source session. i.e. at some point the internal tracked session identity keys (sessid key) for two seperate sessions,
    both previously associated one-to-one with normal api sessions will become two sessid key's associated with two api sessions.
    * We'd likely want to have a warning message + some visual indicator to indicate the confidence of the session tracking is downgraded (this will come up in other cases as well) and start
      tracking on useragent + ip or whatever.
* Look into how various AWS managed assets create sessions
 * Some like the console, or CloudFormation will create a new key for each request without actually making any session modifying calls iirc
 * I can't remember how much of an issue this is, likely makes sense to look into what sessionContext looks like for these calls.

       
* Add testing for logs directory

## Notes 

* SwitchRole and ConsoleLogin
  * Events are not sent through event bridge because they are marked as read only events.
    * AssumeRole can be readonly as well in some cases, I forget when/why though
  * To link to a previous session we only have the role session arn and creation date, if these collide:
    * We won't know which original user made the SwitchRole/ConsoleLogin call.
    * Unless we want to differentiate based on source ip or user agent.
* Include original + chain of event ids in outputted json?

## Type directory notes

Some stuff found in [CloudTrail event type notes](./types), something got messed up in this directory though and some of the files are duplicates currently.

iirc these files are supposed to track different identity type session changes. Both principal, entity, and assume role reduced cloudtrail logs to a common session key (a string) that could be
referenced across all events which should corelate more or less to the principal or entity(?) as well as tracked edges between different principal/entity session keys
as a result of a specific event log (assumerole, etc..).

## Session key and session relationships

How ctail works basically comes down to these two snippets.

For events that result in a session change we normalize some stuff to an intermidiate object that contains the stuff used to identify future sessions:

```
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
```

Both the above internal representation, and future events can then be reduced to a session ID key:

```
	switch i.Type {
	case "IAMUser":
		// IAMUser::12346789012:AIDAXXXXXXXXXXXXXXXXX:me
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
		// Can be in either of the following formats:
		//   AWSAccount::123456789012:AIDAXXXXXXXXXXXXXXXXX
                //   AWSAccount::123456789012:AIDAXXXXXXXXXXXXXXXXX:botocore-session-1661553185
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

	// AwsConsoleSignIn event type will not have a SessionContext
```

With the original session key and target key a session stream will look like:

```
Event1.Id(): AWSAccount::<acct-id>:AIDA...
Event1.Target(): AWSAccount::<acct-id>:AIDA... -> AssumedRole::<arn>:ASIA...:<unix timestamp>
Event2.Id(): AssumedRole::<arn>:ASIA...:<unix timestamp>
```

### SessionContext field

```
SessionContext is null when .userIdentity.type is

     * Role
     * SAMLUser
     * WebIdentityUser
     * AWSService
     * null (`AwsServiceEvent` event type)

   and sometimes when .userIdentity.type is (TODO: why?)
     * IAMUser
```

### SessionIssuer field

```
// SessionIssuer provides information about how the credentials were obtained if the request was made with temporary
// security credentials.
//
// https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html#sessionissuer
//
type SessionIssuer struct {
	// Type can be
	//  * Root
	//  * IAMUser
	//  * Role
	Type string `json:"type"`

	// PrincipalId the internal ID of the entity that was used to get credentials.
	PrincipalId string `json:"principalId"`

	// Arn the source (account, IAM user, or role) that was used to get temporary security credentials
	Arn string `json:"arn"`

	// AccountId is the account that owns the entity that was used to get credentials.
	AccountId string `json:"accountId"`

	// UserName
	//
	// The friendly name of the user or role that issued the session. The value that appears depends on the
	// sessionIssuer identity type.
	//
	//   * Root w/no alias: nil
	//   * Root w/alias: Account alias
	//   * IAMUser: Name of user
	//   * Role: Name of role
	UserName string `json:"userName"`
}
```

### UserIdentity field

This should correspond to the userIdentity key

```
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
	//   A unique identifier for the entity that made the call. For requests made with temporary security credentials,
	//   this value includes the session name that is passed to the AssumeRole, AssumeRoleWithWebIdentity, or
	//   GetFederationToken API call.
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
```

### EventType field
```
	// EventType can be:
	//   * AwsApiCall
	//   * AwsConsoleSignIn
	//     * Attempts to sign in to the AWS Management Console, the AWS Discussion Forums, and the AWS Support Center.
	//     * https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html
	//   * AwsServiceEvent
	//     * These events are created by AWS services but are not directly triggered by a request to a public AWS API.
	//     * https://docs.aws.amazon.com/awscloudtrail/latest/userguide/non-api-aws-service-events.html
	EventType string `json:"eventType,omitempty"`
```

## Miscellaneous

```
type AwsServiceIdentity struct {
	BaseUserIdentity
	InvokedBy string `json:"invokedBy"`
}

type AwsAccountIdentity struct {
	BaseUserIdentity

	// PrincipalId is
	//   * AIDA[A-Z2-7]{16} representing an IAM User.
	//   * AROA[A-Z2-7]{16}:<sessionName> representing a role session.
	PrincipalId string `json:"principalId"`
	AccountId   string `json:"accountId"`

	// Optional InvokedBy field so far only seen this set to "AWS Internal"
	InvokedBy *string `json:"invokedBy"`
}

type RootIdentity struct {
	BaseUserIdentity

	// PrincipalId appears to be the account ID (or alias?)
	PrincipalId string `json:"principalId"`

	// UserName is the account alias if it is seet.
	UserName *string `json:"userName"`

	// Arn is the root ARN (arn:aws:iam::111111111111:root)
	Arn       string `json:"arn"`
	AccountId string `json:"accountId"`

	// AccessKeyId appears to be a temporary token associated with the current account in some way.
	//  * Using https://go.dev/play/p/-VgXwYUfRUC results in the current account ID.
	//  * Haven't seen the same ID occur twice in the logs yet, so unclear atm how to associate this identity.
	//  * It appears ASIA... ids relate to AROA... ids in some predictable way, may be able to use that.
	AccessKeyId string `json:"accessKeyId"`

	// SessionContext so far seems empty except the attributes object
	SessionContext struct {
		SessionIssuer       SessionIssuer `json:"sessionIssuer"`
		WebIdFederationData struct {
		} `json:"webIdFederationData"`
		Attributes struct {
			CreationDate     time.Time `json:"creationDate"`
			MfaAuthenticated string    `json:"mfaAuthenticated"`
		} `json:"attributes"`
	} `json:"sessionContext"`
}

type UserIdentity struct {
	BaseUserIdentity

	PrincipalId    string `json:"principalId"`
	Arn            string `json:"arn"`
	AccountId      string `json:"accountId"`
	AccessKeyId    string `json:"accessKeyId"`
	UserName       string `json:"userName"`
	SessionContext struct {
		SessionIssuer struct {
		} `json:"sessionIssuer"`
		WebIdFederationData struct {
		} `json:"webIdFederationData"`
		Attributes struct {
			CreationDate     time.Time `json:"creationDate"`
			MfaAuthenticated string    `json:"mfaAuthenticated"`
		} `json:"attributes"`
	} `json:"sessionContext"`
	InvokedBy string `json:"invokedBy"`
}

type AssumedRoleIdentity struct {
	BaseUserIdentity

	PrincipalId    string `json:"principalId"`
	Arn            string `json:"arn"`
	AccountId      string `json:"accountId"`
	SessionContext struct {
		SessionIssuer struct {
			Type        string `json:"type"`
			PrincipalId string `json:"principalId"`
			Arn         string `json:"arn"`
			AccountId   string `json:"accountId"`
			UserName    string `json:"userName"`
		} `json:"sessionIssuer"`
		WebIdFederationData struct {
		} `json:"webIdFederationData"`
		Attributes struct {
			CreationDate     time.Time `json:"creationDate"`
			MfaAuthenticated string    `json:"mfaAuthenticated"`
		} `json:"attributes"`
	} `json:"sessionContext"`
}
```
