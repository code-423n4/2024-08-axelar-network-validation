##https://github.com/code-423n4/2024-08-axelar-network/blob/main/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol

Optimize gas usage in the _setup function by utilizing unchecked blocks for the loop. Line :53 
Gas optimization is crucial in smart contracts to reduce costs and improve efficiency.

https://gist.github.com/soccersd/8a6655b599e1a644795c315e1ec76a66