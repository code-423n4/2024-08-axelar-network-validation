# Low-[1] Missing check for allowance amount


# Proof of Concept:
In [_transferFrom](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/interchain-token/ERC20.sol#L80) function it doesnt check if allowance has enough amount. In natspec above the function says `the caller must have allowance for ``sender``'s tokens of at least amount`.

Also in [_spendAllowance](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/interchain-token/InterchainToken.sol#L135) function it doesnt check for `allowance < amount` in natspec says `Must revert if allowance is not sufficient.`

# Recommendation

Check allowance has enough amount

```solidity
function transferFrom(address sender, address recipient, uint256 amount) external virtual override returns (bool) {
        uint256 _allowance = allowance[sender][msg.sender];

        if (_allowance != UINT256_MAX) {
            if(_allowance < amount){
               revert InsufficientAllowance(spender, _allowance , value);
           }
         unchecked {
            _approve(sender, msg.sender, _allowance - amount);
        }
      }

        _transfer(sender, recipient, amount);

        return true;
    }
```

```solidity
 function _spendAllowance(address sender, address spender, uint256 amount) internal override {
        uint256 _allowance = allowance[sender][spender];


         if (_allowance != UINT256_MAX) {
            if(_allowance < amount){
               revert InsufficientAllowance(spender, _allowance , value);
           }
         unchecked {
            _approve(sender, msg.sender, _allowance - amount);
        }
      }
    }
```
# Low-[2] Missing check for contract existence

# Impact:
Low-level call returns success even if the contract is non-existent. This requires a contract existence check before making the low-level call.

# Proof of Concept:
https://github.com/code-423n4/2024-08-axelar-network/blob/0617b016b9ff6490def5be9079ea78d6c6cf993d/interchain-token-service/contracts/InterchainTokenService.sol#L412

https://github.com/code-423n4/2024-08-axelar-network/blob/0617b016b9ff6490def5be9079ea78d6c6cf993d/interchain-token-service/contracts/InterchainTokenService.sol#L1055-L1068


https://github.com/code-423n4/2024-08-axelar-network/blob/0617b016b9ff6490def5be9079ea78d6c6cf993d/interchain-token-service/contracts/InterchainTokenService.sol#L1103

https://github.com/code-423n4/2024-08-axelar-network/blob/0617b016b9ff6490def5be9079ea78d6c6cf993d/interchain-token-service/contracts/InterchainTokenService.sol#L1203

https://github.com/code-423n4/2024-08-axelar-network/blob/0617b016b9ff6490def5be9079ea78d6c6cf993d/interchain-token-service/contracts/InterchainTokenService.sol#L1190

See: “The low-level functions `call`, `delegatecall` and `staticcall` return true as their first return value if the account called is non-existent, as part of the design of the EVM. Account existence must be checked prior to calling if needed.” from https://docs.soliditylang.org/en/v0.8.7/control-structures.html#error-handling-assert-require-revert-and-exceptions

# Recommendation
Check for target contract existence before call.