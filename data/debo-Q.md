## Impact
Detailed description of the impact of this finding.

Missing override Specifier in Overriding Function.

Issue Type: Code Quality / Functionality

The absence of the override specifier in an overriding function can lead to potential confusion in code maintenance, increased chances of errors, and might cause the contract to fail to compile, as Solidity requires explicit indication when a function overrides another. This issue can result in the contract being non-deployable and could impact the contract’s ability to correctly interact with other parts of the system.

The contract attempts to override a function declared in an interface, but it fails to include the required override keyword. This leads to a compilation error in Solidity.

The error message encountered is:
```sol
[ERROR]: Solc experienced a fatal error.

TypeError: Overriding function is missing "override" specifier.
  --> /Users/williamsmith/Desktop/Stuff/2024-08-axelar-network/axelar-gmp-sdk-solidity/contracts/governance/BaseWeightedMultisig.sol:62:5:
   |
62 |     function epoch() external view returns (uint256) {
   |     ^ (Relevant source part starts here and spans across multiple lines).
Note: Overridden function is here:
  --> /Users/williamsmith/Desktop/Stuff/2024-08-axelar-network/axelar-gmp-sdk-solidity/contracts/interfaces/IBaseWeightedMultisig.sol:27:5:
   |
27 |     function epoch() external view returns (uint256);
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

This error occurs because the function epoch() is defined in the IBaseWeightedMultisig interface and is being implemented in the BaseWeightedMultisig contract. In Solidity, when a function overrides another function from a parent contract or an interface, the override specifier must be used.

## Proof of Concept
Provide direct links to all referenced code in GitHub. Add screenshots, logs, or any other relevant proof that illustrates the concept.

Here is the problematic code snippet:
```sol
    function epoch() external view returns (uint256) {
        return _baseWeightedMultisigStorage().epoch;
    }
```

The function is intended to override the declaration in the IBaseWeightedMultisig interface:
```sol
// In IBaseWeightedMultisig.sol

function epoch() external view returns (uint256);
```

However, the override keyword is missing, leading to the compilation error.
## Tools Used
Manual review and MythX.

## Recommended Mitigation Steps

Add the override keyword to the function definition in the BaseWeightedMultisig contract. This explicitly indicates that the function is overriding a parent or interface function, resolving the compilation issue.

The function should be updated as follows:
```sol
// In BaseWeightedMultisig.sol

function epoch() external view override returns (uint256) {
    return _baseWeightedMultisigStorage().epoch;
}
```

This modification ensures that the Solidity compiler recognizes the function as an override of the interface’s function and allows the contract to compile and function correctly.