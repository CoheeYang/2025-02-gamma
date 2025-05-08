### [S-#] TITLE (Root Cause + Impact)

**Description:** 

**Impact:** 

**Proof of Concept:**

**Recommended Mitigation:** 











### [M-1] Unchecked call leading to unexpected interaction with ParaSwap

**Description:** 

From the hardcode address in Arbitrum, we can see that `ParaSwapUtils.sol::swap(address to, bytes memory callData)` expected to call contract `AugustusSwapper`contract, a proxy contract of ParaSwap. 

Firstly it gets `approvalAddress` by `IAugustusSwapper(to).getTokenTransferProxy()`, then approve the  `approvalAddress` .

In the case of `AugustusSwapper`contract in Arbitrum, the `approvalAddress` is 0x216B4B4Ba9F3e719726886d34a177484278Bfcae, which only has a transferFrom function that onlyOwner can call.



`TransferProxy::transferFrom()`,but it did not check the range of function selector



```solidity
    /**
     * @dev Allows owner of the contract to transfer tokens on user's behalf
     * @dev Swapper contract will be the owner of this contract
     * @param token Address of the token
     * @param from Address from which tokens will be transferred
     * @param to Receipent address of the tokens
     * @param amount Amount of tokens to transfer
     */
    function transferFrom(
        address token,
        address from,
        address to,
        uint256 amount
    ) external override onlyOwner {
        // solhint-disable-next-line avoid-tx-origin
        require(from == tx.origin || from.isContract(), "Invalid from address");

        IERC20(token).safeTransferFrom(from, to, amount);
    }
```



After `_validateCallData()` passes, the same bytes parameter named calldata is used to call the vault address`0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57`

```solidity
(bool success, ) = to.call(callData)
```

However, the receiver check can be easily manipulated leading to unexpected function call.

**For example, if the keeper calls a view function that makes no transfer, it won't even be noticed at all.** 

这对上游的函数更新也会有影响，因为明明没有进行swap，但是记录的数据还是被修改了，简单来说，这两个检验只管一个receiver和to的地址



**Impact:** 

This leads to a great disaster that basically anyone can make vault do abitrary call using `swap()` including transfer all the, and `swap()` is the key function used in `PerptualVault.sol` 

```solidity
(bool success, ) = to.call(callData)
```

**Proof of Concept:**Recommended Mitigation:** 