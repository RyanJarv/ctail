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
