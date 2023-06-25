These notes are from approximately October 2022, they are fairly brief so I added additional context in bold in case they happen to be useful to someone.

Additional notes can be found in [./types/...](../../types) in the root directory.

## TODO


* Handle out of order cross-account assume role calls
  * **CloudTrail doesn't guarante event order, so a call using a session can come before the call to create the session itself**
  * The source and target events happen the same second, they can't be sorted on date. **idk**
  * Maybe just need to have fall back ids? **idk**
* Handle representing collisions in the outputted JSON.
  * **Notes (Jun 24th 2023):**
    * **It is possible for two different sessions to have all the same identifying attributes we use to differentiate sessions.
      This happens primarily because access key id get's recycled occasionally and AWS doesn't output session tokens to the logs.
      See [hunters-research-is-aws-recycling-your-access-key](https://www.hunters.security/en/blog/hunters-research-is-aws-recycling-your-access-key)
      for more info.**
    * **This kinda sucks.. but should be able to handle this case. For example to matter to us the collision has to be:**
      1) **Two sessions from the same source principal, otherwise we can tell them apart.**
      2) **Has to happen the same second, otherwise we can tell them apart (based on .userIdentity.sessionContext.attributes.creationDate).**
      3) **some other stuff maybe? i don't remember now..**
    * **In any case, the result will be (in the context of this tool) that we know there is a collision and events by the same session that happen after
      can be one of two principals from the same source session. i.e. at some point the internal tracked session identity keys (sessid key) for two seperate sessions,
      both previously associated one-to-one with normal api sessions will become two sessid key's associated with two api sessions.**
      * **We'd likely want to have a warning message + some visual indicator to indicate the confidence of the session tracking is downgraded (this will come up in other cases as well) and start
        tracking on useragent + ip or whatever.**
 * **Look into how various AWS managed assets create sessions**
   * **Some like the console, or CloudFormation will create a new key for each request without actually making any session modifying calls iirc**
   * **I can't remember how much of an issue this is, likely makes sense to look into what sessionContext looks like for these calls.**

       
* Add testing for logs directory

## Notes 

* SwitchRole and ConsoleLogin
  * Events are not sent through event bridge because they are marked as read only events.
    * **Actually AssumeRole can be readonly as well in some cases, I forget when/why though**
  * To link to a previous session we only have the role session arn and creation date, if these collide:
    * We won't know which original user made the SwitchRole/ConsoleLogin call.
    * Unless we want to differentiate based on source ip or user agent.
* Include original + chain of event ids in outputted json?


### principal tracking only

* Type
    * Same Account
      * Persistent Access **general catagory**
        * **iirc the type names listed where for matching on: .userIdentity.type). descriptions are from the docs somewhere.**
        * Root **principal type**
          * The request was made with your AWS account credentials. If the userIdentity type is Root and you set an
            alias for your account, the userName field contains your account alias.
        * IAMUser **principal type**
          * The request was made with the credentials of an IAM user.
        * Role **principal type**
          * The request was made with a persistent IAM identity that has specific permissions. The issuer of role
            sessions is always the role.
  
      * Session Based Access *general catagory*
        * AssumedRole **principal type**
          * The request was made with temporary security credentials that were obtained with a role by making a call
            to the AWS Security Token Service (AWS STS) AssumeRole API. This can include roles for Amazon EC2 and
            cross-account API access.
        * FederatedUser **principal type**
          * The request was made with temporary security credentials that were obtained via a call to the AWS STS
            GetFederationToken API.

    * Cross-Account Access
    
       AWSAccount and AWSService appear for type in your logs when there is cross-account access using an IAM role
       that you own.
  
       * AWSAccount **principal type**
         * The request was made by another AWS account.
       * AWSService **principal type**
         * The request was made by an AWS account that belongs to an AWS service.
  
    * Other
        * Directory **principal type**
          * The request was made to a directory service, and the type is unknown. Directory services include the
            following: Amazon WorkDocs and Amazon QuickSight.
        * Unknown **principal type**
          * The request was made with an identity type that CloudTrail cannot determine.
  
  
    Undocumented types (**other stuff I found in various logs, I believe the docs mention these but don't go into detail iirc?**:
      * SAMLUser
      * WebIdentityUser
      * WebIdentityUser
      * null
        * Appears to only occur on `AwsServiceEvent` event types.
