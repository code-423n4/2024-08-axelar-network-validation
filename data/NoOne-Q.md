# Low [1] Missing check for allowance amount


In [_transferFrom](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/interchain-token/ERC20.sol#L80) function it doesnt check if allowance has enough amount. In natspec above the function says `the caller must have allowance for ``sender``'s tokens of at least amount`.

Also in [_spendAllowance](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/interchain-token/InterchainToken.sol#L135) function it doesnt check for `allowance < amount` in natspec says `Must revert if allowance is not sufficient.`

# Recomendation

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

