Insufficient payload validation in the execute_message()- as a result, event spamming would cause havoc in front end application when processing them

https://github.com/code-423n4/2024-08-axelar-network/blob/main/axelar-amplifier/interchain-token-service/src/contract/execute.rs#L19-L79

While executing incoming message, amount in the payload when transferring token is not check to see if it is a zero amount sent before updating the state of the contract and emitting event upon completion. As a result of this insufficient input validation on the amount, the function will pass successfully by emitting the event. This can be of a negative effect to the system as these event will be used in the front end application. If these are spammed it could cause unexpected issue when processing them. 

Recommendation
Validate the amount value from the payload
