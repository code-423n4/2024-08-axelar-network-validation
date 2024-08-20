# Incorrect natspec in `WightedMultisigTypes.sol`

## Description

In `WightedMultisigTypes.sol` the `WeightedSigner` struct natspec have one additional @param treshold that does not occurr in the struct.

## Found in

https://github.com/code-423n4/2024-08-axelar-network/blob/main/axelar-gmp-sdk-solidity/contracts/types/WeightedMultisigTypes.sol#L5-L14

## Recommended Mitigation Steps
Remove the `@param treshold`

```diff
/**
 * @notice This struct represents the weighted signers payload
 * @param signers The list of signers
 * @param weights The list of weights
- * @param threshold The threshold for the signers
 */
struct WeightedSigner {
    address signer;
    uint128 weight;
}
```