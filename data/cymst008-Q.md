## https://github.com/code-423n4/2024-08-axelar-network/blob/main/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol

Changing the visibility of the storage variable to internal allows derived contracts to access it directly, enhancing modularity and flexibility in the codebase. Line: 150 

Using require statements in modifiers improves code readability by clearly stating the conditions for execution. It also helps in optimizing gas usage by reverting early if conditions are not met. Line: 36

add event for function call. Line: 80
Events provide a way to log and track important contract actions, enhancing visibility and auditability of the contract operations.

Reentrancy attacks can be a serious vulnerability in smart contracts, allowing malicious users to exploit the contract's state. By adding the nonReentrant modifier, we can prevent these attacks by ensuring that the functions cannot be called recursively Line: 80

