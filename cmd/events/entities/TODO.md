## TODO


* Handle out of order cross-account assume role calls
  * The source and target events happen the same second, they can't be sorted on date.
  * Maybe just need to have fall back ids? 
* Handle representing collisions in the outputted JSON.
* Add testing for logs directory

## Notes 

* SwitchRole and ConsoleLogin
  * Events are not sent through event bridge because they are marked as read only events.
  * To link to a previous session we only have the role session arn and creation date, if these collide:
    * We won't know which original user made the SwitchRole/ConsoleLogin call.
    * Unless we want to differentiate based on source ip or user agent.
* Include original + chain of event ids in outputted json?


### principal tracking only

* Type
    * Same Account
      * Persistent Access
        * Root
          * The request was made with your AWS account credentials. If the userIdentity type is Root and you set an
            alias for your account, the userName field contains your account alias.
        * IAMUser
          * The request was made with the credentials of an IAM user.
        * Role
          * The request was made with a persistent IAM identity that has specific permissions. The issuer of role
            sessions is always the role.
  
      * Session Based Access
        * AssumedRole
          * The request was made with temporary security credentials that were obtained with a role by making a call
            to the AWS Security Token Service (AWS STS) AssumeRole API. This can include roles for Amazon EC2 and
            cross-account API access.
        * FederatedUser
          * The request was made with temporary security credentials that were obtained via a call to the AWS STS
            GetFederationToken API.

    * Cross-Account Access
    
       AWSAccount and AWSService appear for type in your logs when there is cross-account access using an IAM role
       that you own.
  
       * AWSAccount
         * The request was made by another AWS account.
       * AWSService
         * The request was made by an AWS account that belongs to an AWS service.
  
    * Other
        * Directory
          * The request was made to a directory service, and the type is unknown. Directory services include the
            following: Amazon WorkDocs and Amazon QuickSight.
        * Unknown
          * The request was made with an identity type that CloudTrail cannot determine.
  
  
    Undocumented types:
      * SAMLUser
      * WebIdentityUser
      * WebIdentityUser
      * null
        * Appears to only occur on `AwsServiceEvent` event types.
