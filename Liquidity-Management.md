# Liquidity Management - Findings Report

# Table of contents
- ### [Contest Summary](#contest-summary)
- ### [Results Summary](#results-summary)
- ## High Risk Findings
    
    - [H-01. Wrong refundExecutionFee in _handleReturn](#H-01)
    - [H-02. Deposits on long one leverage vault don't actually finalize the flow, leading to a Denial of Service (DoS)](#H-02)
    - [H-03. Loss of fee refund due to premature state deletion in `PerpetualVault::_handleReturn` function](#H-03)
    - [H-04. If users withdraw while a position is in loss, the whole PNL of the position to their withdrawal amount instead of just their share of it.](#H-04)
    - [H-05. Subtracting position fee in position net value will lead to incorrect share allocation](#H-05)
- ## Medium Risk Findings
    - [M-01. Wrong index causes last depositor to always get execution fee refund if cancelFlow is called by keeper to cancel a withdrawal](#M-01)
    - [M-02. PerpetualVault can be completely bricked](#M-02)
    - [M-03. getExecutionGasLimit() reports a lower gas limit due to gasPerSwap miscalculation](#M-03)
    - [M-04. Functions that rely on chainlink prices cannot be queried on avalanche due to sequencer uptime check.](#M-04)
    - [M-05. Incorrect Share Accounting After Liquidation Leading to Ownership Dilution](#M-05)
    - [M-06. User may withdraw more than expected if ADL event happens](#M-06)
    - [M-07. ADL can result in unwrapped ETH as output which is not handled](#M-07)
    - [M-08. Fetching indexToken.balanceOf() will always revert for BTC market](#M-08)
    - [M-09. new deposits be incorrectly rejected due to false "maxCapReached" errors.](#M-09)
- ## Low Risk Findings
    - [L-01. Cancelling a Flow after a Position Is Created Might Result in Inflation/Deflation of Shares](#L-01)
    - [L-02. Fees not refunded to users on position closed and funds locked/lost](#L-02)
    - [L-03. Incorrect Token Price Validation in KeeperProxy](#L-03)
    - [L-04. Protocol Recovery Mechanism at Risk Due to Unhandled Token Transfer Failures](#L-04)
    - [L-05. `_withdraw` function uses `shortTokenPrice.max` instead of `shortTokenPrice.min` when computing negative PnL adjustment, leading to underestimation of losses and excessive collateral withdrawal](#L-05)
    - [L-06. PerpetualVault withdrawals are affected by global parameter updates](#L-06)
    - [L-07. If Vault Was Liquidated And There Was A Withdrawal Flow Then Fee Should Be Refunded](#L-07)
    - [L-08. Calculating price impact collateral is incorrect when calculating users' increase from deposit](#L-08)
    - [L-09. Settlement Flow Can Be Disrupted When Market Decrease Order is Disabled](#L-09)
    - [L-10. `positionIsClosed` not being set to `true` leads to new position being opened on GMX without a signal from offchain, and users not receiving execution fee refund](#L-10)
    - [L-11. Locked funds due to overflow via shares decimal scaling](#L-11)
    - [L-12.  Execution Fee Refund Issue in `cancelFlow` Leading to Potential Revert](#L-12)
    - [L-13. indexToken should be swapped to collateralToken before Compound action](#L-13)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: Gamma

### Dates: Feb 11th, 2025 - Feb 25th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-02-gamma)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 5
   - Medium: 9
   - Low: 13


# High Risk Findings

## <a id='H-01'></a>H-01. Wrong refundExecutionFee in _handleReturn

_Submitted by [anchabadze](https://profiles.cyfrin.io/u/anchabadze), [matic68](https://profiles.cyfrin.io/u/matic68), [typical_human](https://profiles.cyfrin.io/u/typical_human), [acai](https://profiles.cyfrin.io/u/acai), [incogknito](https://profiles.cyfrin.io/u/incogknito), [riceee](https://profiles.cyfrin.io/u/riceee), [cipherhawk](https://profiles.cyfrin.io/u/cipherhawk), [danzero](https://profiles.cyfrin.io/u/danzero), [sparrowblck](https://profiles.cyfrin.io/u/sparrowblck), [y4y](https://profiles.cyfrin.io/u/y4y), [0xkyosi](https://profiles.cyfrin.io/u/0xkyosi), [harry_cryptodev](https://profiles.cyfrin.io/u/harry_cryptodev), [secret__one](https://profiles.cyfrin.io/u/secret__one), [pengu](https://profiles.cyfrin.io/u/pengu), [bigsam](https://profiles.cyfrin.io/u/bigsam), [dharkartz](https://profiles.cyfrin.io/u/dharkartz), [udo](https://profiles.cyfrin.io/u/udo), [sauronsol](https://profiles.cyfrin.io/u/sauronsol), [0xnforcer](https://profiles.cyfrin.io/u/0xnforcer), [0xrststn](https://profiles.cyfrin.io/u/0xrststn), [0xakira](https://profiles.cyfrin.io/u/0xakira), [bladesec](https://profiles.cyfrin.io/u/bladesec). Selected submission by: [danzero](https://profiles.cyfrin.io/u/danzero)._      
            


## Summary

Refund execution fee logic within the `_handleReturn` function use the wrong argument which causes the execution fee being refunded to the wrong recipient.

## Vulnerability Details

Below is a snippet of the `_handleReturn`function from `PerpetualVault.sol`:

```solidity
/**
   * @notice this function is an end of withdrawal flow.
   * @dev should update all necessary global state variables
   * 
   * @param withdrawn amount of token withdrawn from the position
   * @param positionClosed true when position is closed completely by withdrawing all funds, or false
   */
  function _handleReturn(uint256 withdrawn, bool positionClosed, bool refundFee) internal {
    (uint256 depositId) = flowData;
    uint256 shares = depositInfo[depositId].shares;
    uint256 amount;
    if (positionClosed) {
      amount = collateralToken.balanceOf(address(this)) * shares / totalShares;
    } else {
      uint256 balanceBeforeWithdrawal = collateralToken.balanceOf(address(this)) - withdrawn;
      amount = withdrawn + balanceBeforeWithdrawal * shares / totalShares;
    }
    if (amount > 0) {
      _transferToken(depositId, amount);
    }
    emit Burned(depositId, depositInfo[depositId].recipient, depositInfo[depositId].shares, amount);
    _burn(depositId);

    if (refundFee) {
      uint256 usedFee = callbackGasLimit * tx.gasprice;
      if (depositInfo[depositId].executionFee > usedFee) {
        try IGmxProxy(gmxProxy).refundExecutionFee(depositInfo[counter].owner, depositInfo[counter].executionFee - usedFee) {} catch {}
      }
    }

    // update global state
    delete swapProgressData;
    delete flowData;
    delete flow;
  }
```

In the if `refundFee` block, it performs a check on `depositInfo[depositId].executionFee` but then uses `depositInfo[counter]` when calling `refundExecutionFee`. `counter` is a state variable that only increment by 1 when there is a new deposit, while `depositId` comes from the `flowData` which is updated with the value of the intended deposit id of the user that requested withdrawal.

Consider this scenario:

1. User A deposits funds, the contract increments the `counter` to `1` and the contract assigns a deposit ID of `1`. In the deposit record `depositInfo[1]`, User A has an `executionFee` of 1 ETH.
2. Shortly after, User B deposits funds, and the contract increments the `counter` to `2`, creating `depositInfo[2]` with an `executionFee` of 1.2 ETH.
3. User A initiates a withdrawal that triggers the `_handleReturn` function with `depositId` `1`.
4. Inside `_handleReturn`, the function calculates `usedFee` (for example, 0.1 ETH) and checks that `depositInfo[1].executionFee` (1 ETH) is greater than `usedFee`.

   **Intended Behavior:** The refund should be calculated as `1 ETH - 0.1 ETH = 0.9 ETH` and be sent to User A.

   **Actual Behavior:** Due to the bug, the refund call uses `depositInfo[2]` instead of `depositInfo[1]`. As a result, the function refunds `1.2 ETH - 0.1 ETH = 1.1 ETH` to User B instead of refunding User A.



It is noteworthy that this function will only hit the refund logic if the owner need to change the flow state to `WITHDRAW` through the `setVaultState`function, because the only instance where `_handleReturn` is called with the `refundFee` parameter set to true is in the   `_runSwap`function which can be called manually through the `runNextAction`function by the keeper.



## Impact

Execution fee is refunded to the wrong user with the wrong amount.

## Tools Used

Manual review

## Recommendations

Replace `depositInfo[counter]` with `depositInfo[depositId]` in the refund fee block to ensure that the refund logic correctly references the intended deposit.

## <a id='H-02'></a>H-02. Deposits on long one leverage vault don't actually finalize the flow, leading to a Denial of Service (DoS)

_Submitted by [harry_cryptodev](https://profiles.cyfrin.io/u/harry_cryptodev), [sakshamseth5](https://profiles.cyfrin.io/u/sakshamseth5), [0xjoyboy03](https://profiles.cyfrin.io/u/0xjoyboy03), [bizarro](https://profiles.cyfrin.io/u/bizarro), [riceee](https://profiles.cyfrin.io/u/riceee), [bugs_bunny](https://profiles.cyfrin.io/u/bugs_bunny), [fresh](https://profiles.cyfrin.io/u/fresh), [mohitisimmortal](https://profiles.cyfrin.io/u/mohitisimmortal), [jokerstudio](https://profiles.cyfrin.io/u/jokerstudio), [0xkyosi](https://profiles.cyfrin.io/u/0xkyosi), [0xl33](https://profiles.cyfrin.io/u/0xl33), [wellbyt3](https://profiles.cyfrin.io/u/wellbyt3), [leogold](https://profiles.cyfrin.io/u/leogold), [den_dokka](https://profiles.cyfrin.io/u/den_dokka), [cybrid](https://profiles.cyfrin.io/u/cybrid), [phoenix](https://profiles.cyfrin.io/u/phoenix), [mrmorningstar](https://profiles.cyfrin.io/u/mrmorningstar), [vinica_boy](https://profiles.cyfrin.io/u/vinica_boy), [drynooo](https://profiles.cyfrin.io/u/drynooo), [atharv181](https://profiles.cyfrin.io/u/atharv181), [izuman](https://profiles.cyfrin.io/u/izuman), [pkqs90](https://profiles.cyfrin.io/u/pkqs90), [wickie](https://profiles.cyfrin.io/u/wickie), [0xrststn](https://profiles.cyfrin.io/u/0xrststn), [dhank](https://profiles.cyfrin.io/u/dhank). Selected submission by: [jokerstudio](https://profiles.cyfrin.io/u/jokerstudio)._      
            


## Summary
The Gamma protocol utilizes the `flow` and `nextAction` to keep track of the current flow progress. The current flow needs to be finalized before doing another flow. However, for the long one leverage vault, the deposit flow don't actually finalize the flow, which prevents another flow from proceeding, leading to DoS.

## Vulnerability Details
When the position is opened, the `PerpetualVault::deposit` function will set the `flow` to `DEPOSIT` and the `nextAction` to `INCREASE_ACTION`, then leaves the Keeper call `PerpetualVault::runNextAction` function to finalize the deposit flow.
```solidity
  function deposit(uint256 amount) external nonReentrant payable {
    _noneFlow();
    if (depositPaused == true) {
      revert Error.Paused();
    }
    if (amount < minDepositAmount) {
      revert Error.InsufficientAmount();
    }
    if (totalDepositAmount + amount > maxDepositAmount) {
      revert Error.ExceedMaxDepositCap();
    }
@>  flow = FLOW.DEPOSIT;
    collateralToken.safeTransferFrom(msg.sender, address(this), amount);
    counter++;
    depositInfo[counter] = DepositInfo(amount, 0, msg.sender, 0, block.timestamp, address(0));
    totalDepositAmount += amount;
    EnumerableSet.add(userDeposits[msg.sender], counter);

    if (positionIsClosed) {
      MarketPrices memory prices;
      _mint(counter, amount, false, prices);
      _finalize(hex'');
    } else {
      _payExecutionFee(counter, true);
      // mint share token in the NextAction to involve off-chain price data and improve security
@>    nextAction.selector = NextActionSelector.INCREASE_ACTION;
      nextAction.data = abi.encode(beenLong);
    }
  }
```

However, if the vault islong one leverage, when the `PerpetualVault::runNextAction` function calls the `PerpetualVault::_runSwap` function, if the given metadata set to swap only on ParaSwap, the process just mints the shares without finalizing the deposit flow. Consequently, the flow remains unfinalized.
```solidity
  function runNextAction(MarketPrices memory prices, bytes[] memory metadata) external nonReentrant gmxLock {
    _onlyKeeper();
    Action memory _nextAction = nextAction;
    delete nextAction;
    if (_nextAction.selector == NextActionSelector.INCREASE_ACTION) {
      (bool _isLong) = abi.decode(_nextAction.data, (bool));

      if (_isLongOneLeverage(_isLong)) {
 @>     _runSwap(metadata, true, prices);
      } else {
    
    ...
  }
```
```solidity
  function _runSwap(bytes[] memory metadata, bool isCollateralToIndex, MarketPrices memory prices) internal returns (bool completed) {
    if (metadata.length == 0) {
      revert Error.InvalidData();
    }
    if (metadata.length == 2) {
      (PROTOCOL _protocol, bytes memory data) = abi.decode(metadata[0], (PROTOCOL, bytes));
      if (_protocol != PROTOCOL.DEX) {
        revert Error.InvalidData();
      }
      swapProgressData.swapped = swapProgressData.swapped + _doDexSwap(data, isCollateralToIndex);
      
      (_protocol, data) = abi.decode(metadata[1], (PROTOCOL, bytes));
      if (_protocol != PROTOCOL.GMX) {
        revert Error.InvalidData();
      }

      _doGmxSwap(data, isCollateralToIndex);
      return false;
    } else {
      if (metadata.length != 1) {
        revert Error.InvalidData();
      }
      (PROTOCOL _protocol, bytes memory data) = abi.decode(metadata[0], (PROTOCOL, bytes));
      if (_protocol == PROTOCOL.DEX) {
        uint256 outputAmount = _doDexSwap(data, isCollateralToIndex);
        
        // update global state
        if (flow == FLOW.DEPOSIT) {
          // last `depositId` equals with `counter` because another deposit is not allowed before previous deposit is completely processed
@>        _mint(counter, outputAmount + swapProgressData.swapped, true, prices);
        } else if (flow == FLOW.WITHDRAW) {
          _handleReturn(outputAmount + swapProgressData.swapped, false, true);
        } else {
          // in the flow of SIGNAL_CHANGE, if `isCollateralToIndex` is true, it is opening position, or closing position
          _updateState(!isCollateralToIndex, isCollateralToIndex);
        }
        
        return true;
      } else {
        _doGmxSwap(data, isCollateralToIndex);
        return false;
      }
    }
  }
```


## Impact

This causes a Denial of Service (DoS) for the long one leverage vault, rendering the vault useless since it cannot proceed with another flow.

Please note that although the protocol had the `PerpetualVault::cancelFlow` and `PerpetualVault::setVaultState` functions that allow forcing cancellation or setting the flow states directly. However, these functions are not designed for this situation.


## PoC
1. Copy the following test case to the `test/PerpetualVault.t.sol` file
2. Run test with `forge test --mt test_Revert_1xLongPosition_With_MultipleDeposits --rpc-url arbitrum`

```solidity
  function test_Revert_1xLongPosition_With_MultipleDeposits() external {
    address keeper = PerpetualVault(vault).keeper();
    address alice = makeAddr("alice");
    depositFixture(alice, 1e10);

    MarketPrices memory prices = mockData.getMarketPrices();
    bytes memory paraSwapData = mockData.getParaSwapData(vault);
    bytes[] memory swapData = new bytes[](1);
    swapData[0] = abi.encode(PROTOCOL.DEX, paraSwapData);
    vm.prank(keeper);
    PerpetualVault(vault).run(true, true, prices, swapData);

    uint256 executionFeeGasLimit = PerpetualVault(vault).getExecutionGasLimit(true);
    uint256 executionFee = executionFeeGasLimit * tx.gasprice;

    // bob's deposit after position is opened
    address bob = makeAddr("bob");
    deal(bob, executionFee);
    depositFixture(bob, 1e10);
    vm.prank(keeper);
    PerpetualVault(vault).runNextAction(prices, swapData);
    assertEq(uint8(PerpetualVault(vault).flow()), 1); // the flow still be DEPOSIT although bob's deposit is done

    // chris's deposit after bob's deposit
    address chris = makeAddr("chris");
    deal(chris, executionFee);
    IERC20 collateralToken = PerpetualVault(vault).collateralToken();
    vm.startPrank(chris);
    deal(address(collateralToken), chris, 1e10);
    
    collateralToken.approve(vault, 1e10);
    vm.expectRevert(Error.FlowInProgress.selector); // tx will be reverted due to the bob's deposit is not finalized the flow.
    PerpetualVault(vault).deposit{value: executionFee}(1e10);
    vm.stopPrank();
  }

```

## Tools Used
Manual Review


## Recommendations
Within the `PerpetualVault::runNextAction` function, after the `_runSwap` function is called, the flow should be finalized by calling the `_finalize` function.
```diff
  function runNextAction(MarketPrices memory prices, bytes[] memory metadata) external nonReentrant gmxLock {
    _onlyKeeper();
    Action memory _nextAction = nextAction;
    delete nextAction;
    if (_nextAction.selector == NextActionSelector.INCREASE_ACTION) {
      (bool _isLong) = abi.decode(_nextAction.data, (bool));

      if (_isLongOneLeverage(_isLong)) {
       _runSwap(metadata, true, prices);
+      _finalize(hex'');
      } else {
    
    ...
  }
```
## <a id='H-03'></a>H-03. Loss of fee refund due to premature state deletion in `PerpetualVault::_handleReturn` function

_Submitted by [parth](https://profiles.cyfrin.io/u/parth), [biakia](https://profiles.cyfrin.io/u/biakia), [sakshamseth5](https://profiles.cyfrin.io/u/sakshamseth5), [bigsam](https://profiles.cyfrin.io/u/bigsam), [riceee](https://profiles.cyfrin.io/u/riceee), [jokerstudio](https://profiles.cyfrin.io/u/jokerstudio), [olami9783](https://profiles.cyfrin.io/u/olami9783), [mikebello](https://profiles.cyfrin.io/u/mikebello), [y4y](https://profiles.cyfrin.io/u/y4y), [0xkyosi](https://profiles.cyfrin.io/u/0xkyosi), [harry_cryptodev](https://profiles.cyfrin.io/u/harry_cryptodev), [codexbugmenot](https://profiles.cyfrin.io/u/codexbugmenot), [secret__one](https://profiles.cyfrin.io/u/secret__one), [den_dokka](https://profiles.cyfrin.io/u/den_dokka), [0xakira](https://profiles.cyfrin.io/u/0xakira), [mrmorningstar](https://profiles.cyfrin.io/u/mrmorningstar), [fuzzysquirrel](https://profiles.cyfrin.io/u/fuzzysquirrel), [dharkartz](https://profiles.cyfrin.io/u/dharkartz), [udo](https://profiles.cyfrin.io/u/udo), [0xrststn](https://profiles.cyfrin.io/u/0xrststn), [0xodus](https://profiles.cyfrin.io/u/0xodus), [bhorprakash](https://profiles.cyfrin.io/u/bhorprakash), [bladesec](https://profiles.cyfrin.io/u/bladesec), [dhank](https://profiles.cyfrin.io/u/dhank), [null](https://profiles.cyfrin.io/u/null). Selected submission by: [jokerstudio](https://profiles.cyfrin.io/u/jokerstudio)._      
            


## Summary

The Gamma protocol will refund the excess execution fee to the user when the flow is finalized. However, the `PerpetualVault::_handleReturn` function has a flaw logic that does not properly refund fees, which causes any flow that ends with this function to be affected by this vulnerability.

## Vulnerability Details

The `PerpetualVault::_handleReturn` function is used in the withdraw and signal change flows. This function comprises the burn and refund processes. However, the burn process is called before the refund process, which causes the `depositInfo[depositId]` to be deleted before the refund process. Consequently, the `depositInfo[depositId].executionFee` is always 0, causing the refund condition to never be met.

```solidity
  function _handleReturn(uint256 withdrawn, bool positionClosed, bool refundFee) internal {
    (uint256 depositId) = flowData;
    uint256 shares = depositInfo[depositId].shares;
    uint256 amount;
    if (positionClosed) {
      amount = collateralToken.balanceOf(address(this)) * shares / totalShares;
    } else {
      uint256 balanceBeforeWithdrawal = collateralToken.balanceOf(address(this)) - withdrawn;
      amount = withdrawn + balanceBeforeWithdrawal * shares / totalShares;
    }
    if (amount > 0) {
      _transferToken(depositId, amount);
    }
    emit Burned(depositId, depositInfo[depositId].recipient, depositInfo[depositId].shares, amount);
@>  _burn(depositId);

    if (refundFee) {
      uint256 usedFee = callbackGasLimit * tx.gasprice;
@>    if (depositInfo[depositId].executionFee > usedFee) {
        try IGmxProxy(gmxProxy).refundExecutionFee(depositInfo[counter].owner, depositInfo[counter].executionFee - usedFee) {} catch {}
      }
    }

    // update global state
    delete swapProgressData;
    delete flowData;
    delete flow;
  }
```

```solidity
  function _burn(uint256 depositId) internal {
    EnumerableSet.remove(userDeposits[depositInfo[depositId].owner], depositId);
    totalShares = totalShares - depositInfo[depositId].shares;
@>  delete depositInfo[depositId];
  }
```

## Impact

Any flows that ends with the `PerpetualVault::_handleReturn` function by the `refundFee = true` will be affected by this vulnerability. Especially, the `PerpetualVault::_payExecutionFee` function allows the user to send arbitrary amount excess the estimated execution fee without restriction. Consequently, the user will lose all fee without getting any refund and the execution fee becomes stuck in the `GmxProxy` contract.

Please note that although the protocol has the `GmxProxy::withdrawEth` function that allows owner withdraw ethers in some accident. However, this function should not be called in the normal flow.

## PoC

This PoC demonstrates withdrawing on the long one leverage vault which is one of the example flow that call the `PerpetualVault::_handleReturn` function to refund the execution fee.

1. Copy the `getParaSwapData_Index_To_Collateral` function to the `test/mock/MockData.sol` for support swap index token back to collateral token for withdraw flow.
2. Copy the following test case to the `test/PerpetualVault.t.sol` file
3. Run test with `forge test --mt test_Loss_Of_GasFeeRefund_When_Withdraw --rpc-url arbitrum`

```solidity
  function getParaSwapData_Index_To_Collateral(address receiver) external pure returns (bytes memory) {
    bytes memory rev = abi.encodePacked(receiver);
    bytes memory original = hex'000000000000000000000000def171fe48cf0115b1d80b88dc8eab59176fee57000000000000000000000000000000000000000000000000287a7d29bb1d81ed000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000007c446c67b6d000000000000000000000000000000000000000000000000000000000000002000000000000000000000000082af49447d8a07e3bd95bd0d56f35241523fbab1000000000000000000000000000000000000000000000000287a7d29bb1d81ed00000000000000000000000000000000000000000000000000000002440be40000000000000000000000000000000000000000000000000000000002540be400000000000000000000000000919c94b69950449cea621fd6cc0cb538de79d0dd000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000078000000000000000000000000000000000000000000000000000000000679cf4ce161d4b0c6e2e4ca381c524a0776f557100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000002710000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000af88d065e77c8cc2239327c5edb3a432268e5831000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000058a5f0b73969800faff8556cd2187e3fce71a6cb0000000000000000000000000000000000000000000000000000000000001f40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000070000000000000000000000001f721e2e82f6676fce4ea07a5958cf098d339e18000000000000000000000000000000000000000000000000000000000000271000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000067a62e220000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002882af49447d8a07e3bd95bd0d56f35241523fbab1af88d065e77c8cc2239327c5edb3a432268e5831000000000000000000000000000000000000000000000000000000000000000000000000369a2fdb910d432f0a07381a5e3d27572c87671300000000000000000000000000000000000000000000000000000000000007d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000030000000000000000000000001b81d678ffb9c0263b24a97847620c99d213eb14000000000000000000000000000000000000000000000000000000000000271000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000067a62e22000000000000000000000000000000000000000000000000000000000000002b82af49447d8a07e3bd95bd0d56f35241523fbab1000064af88d065e77c8cc2239327c5edb3a432268e5831000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

    bytes memory result = original;

    assembly {
      let originalPtr := add(result, 0x20)
      let replacementPtr := add(rev, 0x20)

      for {let i := 0} lt(i, mload(rev)) { i := add(i, 0x20) } {
        mstore(add(originalPtr, add(304, i)), mload(add(replacementPtr, i)))
      }
    }
    require(original.length == result.length, "fail");
    return result;
  }
```

```solidity
  function test_Loss_Of_GasFeeRefund_When_Withdraw() external {
    address keeper = PerpetualVault(vault).keeper();
    address gmxProxy = address(PerpetualVault(vault).gmxProxy());
    uint256 gmxProxyBalBefore = gmxProxy.balance;
    address alice = makeAddr("alice");
    depositFixture(alice, 1e10);

    MarketPrices memory prices = mockData.getMarketPrices();
    bytes memory paraSwapData = mockData.getParaSwapData(vault);
    bytes[] memory swapData = new bytes[](1);
    swapData[0] = abi.encode(PROTOCOL.DEX, paraSwapData);
    vm.prank(keeper);
    PerpetualVault(vault).run(true, true, prices, swapData);

    uint256 lockTime = 1;
    PerpetualVault(vault).setLockTime(lockTime);
    vm.warp(block.timestamp + lockTime + 1);

    paraSwapData = mockData.getParaSwapData_Index_To_Collateral(vault);
    swapData = new bytes[](1);
    swapData[0] = abi.encode(PROTOCOL.DEX, paraSwapData);
    uint256[] memory depositIds = PerpetualVault(vault).getUserDeposits(alice);
    deal(alice, 1 ether);
    vm.prank(alice);
    PerpetualVault(vault).withdraw{value: alice.balance}(alice, depositIds[0]); // alice mistakenly sent all balance of ether as execution fee

    vm.prank(keeper);
    PerpetualVault(vault).runNextAction(prices, swapData);

    // withdrawal flow is finalized
    uint8 flow = uint8(PerpetualVault(vault).flow());
    assertEq(flow, 0);
    (PerpetualVault.NextActionSelector selector, ) = PerpetualVault(vault).nextAction();
    assertEq(uint8(selector), 0);

    assertEq(alice.balance, 0); // alice loss all ether without getting any refund
    assertEq(gmxProxy.balance, gmxProxyBalBefore + 1 ether); // alice`s execution fee becomes stuck in the GmxProxy contract!
  }
```

## Tools Used

Manual Review

## Recommendations

Within the `PerpetualVault::_handleReturn` function, bring the burn process to execute after refunding the execution fee process.

```diff
  function _handleReturn(uint256 withdrawn, bool positionClosed, bool refundFee) internal {
    (uint256 depositId) = flowData;
    uint256 shares = depositInfo[depositId].shares;
    uint256 amount;
    if (positionClosed) {
      amount = collateralToken.balanceOf(address(this)) * shares / totalShares;
    } else {
      uint256 balanceBeforeWithdrawal = collateralToken.balanceOf(address(this)) - withdrawn;
      amount = withdrawn + balanceBeforeWithdrawal * shares / totalShares;
    }
    if (amount > 0) {
      _transferToken(depositId, amount);
    }
-   emit Burned(depositId, depositInfo[depositId].recipient, depositInfo[depositId].shares, amount);
-  _burn(depositId);

    if (refundFee) {
      uint256 usedFee = callbackGasLimit * tx.gasprice;
      if (depositInfo[depositId].executionFee > usedFee) {
        try IGmxProxy(gmxProxy).refundExecutionFee(depositInfo[counter].owner, depositInfo[counter].executionFee - usedFee) {} catch {}
      }
    }

+   emit Burned(depositId, depositInfo[depositId].recipient, depositInfo[depositId].shares, amount);
+   _burn(depositId);

    // update global state
    delete swapProgressData;
    delete flowData;
    delete flow;
  }
```

## <a id='H-04'></a>H-04. If users withdraw while a position is in loss, the whole PNL of the position to their withdrawal amount instead of just their share of it.

_Submitted by [novaman33](https://profiles.cyfrin.io/u/novaman33), [t0x1c](https://profiles.cyfrin.io/u/t0x1c), [vinica_boy](https://profiles.cyfrin.io/u/vinica_boy), [mrmorningstar](https://profiles.cyfrin.io/u/mrmorningstar), [dingo2077](https://profiles.cyfrin.io/u/dingo2077), [0xmechanic](https://profiles.cyfrin.io/u/0xmechanic), [harry_cryptodev](https://profiles.cyfrin.io/u/harry_cryptodev), [pkqs90](https://profiles.cyfrin.io/u/pkqs90), [wickie](https://profiles.cyfrin.io/u/wickie), [0xdice91](https://profiles.cyfrin.io/u/0xdice91). Selected submission by: [wickie](https://profiles.cyfrin.io/u/wickie)._      
            


## Summary

When a user withdraw while a short or long with more than 1x leverage is open, the vault first settles the fee via PerpetualVault.sol::settle() and calls \_withdraw() in the next action executed by the keeper. When calculating how much to withdraw for the user depending on his shares, the vault applies the whole PNL of the position instead of the user's share of PNL due to wrong boolean input in VaultReader.sol::getPnl(). If the position is in loss, the PNL will return a negative value, which will be deducted from the user's withdrawing collateral amount. If a user's collateral is less than the PNL of the whole position, it will revert with an underflow error. If he has enough collateral, he will be taking on all the loss of the position instead of just his share of loss.

## Vulnerability Details

In [\_withdraw()](https://github.com/CodeHawks-Contests/2025-02-gamma/blob/84b9da452fc84762378481fa39b4087b10bab5e0/contracts/PerpetualVault.sol#L1089), when a short or long with more than 1x leverage position is open, it calculates the user's collateral, size in usd value and fee amount to pay based on his shares.

```solidity
  function _withdraw(uint256 depositId, bytes memory metadata, MarketPrices memory prices) internal {
    uint256 shares = depositInfo[depositId].shares;
    if (shares == 0) {
      revert Error.ZeroValue();
    }
    
    if (positionIsClosed) {
      _handleReturn(0, true, false);
    } else if (_isLongOneLeverage(beenLong)) {  // beenLong && leverage == BASIS_POINTS_DIVISOR
      uint256 swapAmount = IERC20(indexToken).balanceOf(address(this)) * shares / totalShares;
      nextAction.selector = NextActionSelector.SWAP_ACTION;
      // abi.encode(swapAmount, swapDirection): if swap direction is true, swap collateralToken to indexToken
      nextAction.data = abi.encode(swapAmount, false);
    } else if (curPositionKey == bytes32(0)) {    // vault liquidated
      _handleReturn(0, true, false);
    } else {
      IVaultReader.PositionData memory positionData = vaultReader.getPositionInfo(curPositionKey, prices);
      uint256 collateralDeltaAmount = positionData.collateralAmount * shares / totalShares;
      uint256 sizeDeltaInUsd = positionData.sizeInUsd * shares / totalShares;
      // we always charge the position fee of negative price impact case.
      uint256 feeAmount = vaultReader.getPositionFeeUsd(market, sizeDeltaInUsd, false) / prices.shortTokenPrice.max;
@>    int256 pnl = vaultReader.getPnl(curPositionKey, prices, sizeDeltaInUsd);
      if (pnl < 0) {
        collateralDeltaAmount = collateralDeltaAmount - feeAmount - uint256(-pnl) / prices.shortTokenPrice.max;
      } else {
        collateralDeltaAmount = collateralDeltaAmount - feeAmount;
      }
      uint256 acceptablePrice = abi.decode(metadata, (uint256));
      _createDecreasePosition(collateralDeltaAmount, sizeDeltaInUsd, beenLong, acceptablePrice, prices);
    }
  }
```

In order to get the PNL of the user's share, the function calls [VaultReader.getPnl()](https://github.com/CodeHawks-Contests/2025-02-gamma/blob/84b9da452fc84762378481fa39b4087b10bab5e0/contracts/VaultReader.sol#L171), which fetch the position info from GMX.

```solidity
  function getPnl(
    bytes32 key,
    MarketPrices memory prices,
    uint256 sizeDeltaUsd
  ) external view returns (int256) {
    uint256 sizeInTokens = getPositionSizeInUsd(key);
    if (sizeInTokens == 0) return 0;
    
    PositionInfo memory positionInfo = gmxReader.getPositionInfo(
      address(dataStore),
      referralStorage,
      key,
      prices,
      sizeDeltaUsd,
      address(0),
@>    true
    );

    return positionInfo.pnlAfterPriceImpactUsd;
  }
```

When calling [getPositionInfo()](https://github.com/gmx-io/gmx-synthetics/blob/ca84cb460b031a867ac193ad241d230bb6c2f840/contracts/reader/Reader.sol#L78) on the gmxReader, is passed in true for the last input parameter. This is a mistake as it makes the function returns the whole position's PNL and not based on the position size in usd value of the user.

```solidity
    function getPositionInfo(
        DataStore dataStore,
        IReferralStorage referralStorage,
        bytes32 positionKey,
        MarketUtils.MarketPrices memory prices,
        uint256 sizeDeltaUsd,
        address uiFeeReceiver,
@>      bool usePositionSizeAsSizeDeltaUsd
    ) public view returns (ReaderPositionUtils.PositionInfo memory) {
        return
            ReaderPositionUtils.getPositionInfo(
                dataStore,
                referralStorage,
                positionKey,
                prices,
                sizeDeltaUsd,
                uiFeeReceiver,
@>              usePositionSizeAsSizeDeltaUsd
            );
    }
```

In GMX's [ReaderPositionUtils.sol::getPositionInfo()](https://github.com/gmx-io/gmx-synthetics/blob/ca84cb460b031a867ac193ad241d230bb6c2f840/contracts/reader/ReaderPositionUtils.sol#L158), it calls the internal version of the function.

```solidity
    function getPositionInfo(
        DataStore dataStore,
        IReferralStorage referralStorage,
        bytes32 positionKey,
        MarketUtils.MarketPrices memory prices,
        uint256 sizeDeltaUsd,
        address uiFeeReceiver,
        bool usePositionSizeAsSizeDeltaUsd
    ) public view returns (PositionInfo memory) {
        Position.Props memory position = PositionStoreUtils.get(dataStore, positionKey);
        return getPositionInfo(
            dataStore,
            referralStorage,
            position,
            prices,
            sizeDeltaUsd,
            uiFeeReceiver,
@>          usePositionSizeAsSizeDeltaUsd
        );
    }
```

In the [internal version](https://github.com/gmx-io/gmx-synthetics/blob/ca84cb460b031a867ac193ad241d230bb6c2f840/contracts/reader/ReaderPositionUtils.sol#L179), when this is true it sets the `sizeDeltaInUsd` variable(which was the user's share of usd value of the position) to the position's usd value.

```solidity
    function getPositionInfo(
        DataStore dataStore,
        IReferralStorage referralStorage,
        Position.Props memory position,
        MarketUtils.MarketPrices memory prices,
        uint256 sizeDeltaUsd,
        address uiFeeReceiver,
        bool usePositionSizeAsSizeDeltaUsd
    ) internal view returns (PositionInfo memory) {
        if (position.account() == address(0)) {
            revert Errors.EmptyPosition();
        }

        PositionInfo memory positionInfo;
        GetPositionInfoCache memory cache;

        positionInfo.position = position;
        cache.market = MarketStoreUtils.get(dataStore, positionInfo.position.market());
        cache.collateralTokenPrice = MarketUtils.getCachedTokenPrice(positionInfo.position.collateralToken(), cache.market, prices);

@>      if (usePositionSizeAsSizeDeltaUsd) {
            sizeDeltaUsd = positionInfo.position.sizeInUsd();
        }
        ....
     (positionInfo.basePnlUsd, positionInfo.uncappedBasePnlUsd, /* sizeDeltaInTokens */) = PositionUtils.getPositionPnlUsd(
            dataStore,
            cache.market,
            prices,
            positionInfo.position,
            sizeDeltaUsd
        );
```

which is later used to calculate the position's PNL via [PositionUtils.sol::getPositionPnlUsd()](https://github.com/gmx-io/gmx-synthetics/blob/ca84cb460b031a867ac193ad241d230bb6c2f840/contracts/position/PositionUtils.sol#L176).

```solidity
    function getPositionPnlUsd(
        DataStore dataStore,
        Market.Props memory market,
        MarketUtils.MarketPrices memory prices,
        Position.Props memory position,
        uint256 sizeDeltaUsd
    ) public view returns (int256, int256, uint256) {
        GetPositionPnlUsdCache memory cache;

        uint256 executionPrice = prices.indexTokenPrice.pickPriceForPnl(position.isLong(), false);

        // position.sizeInUsd is the cost of the tokens, positionValue is the current worth of the tokens
        cache.positionValue = (position.sizeInTokens() * executionPrice).toInt256();
        cache.totalPositionPnl = position.isLong() ? cache.positionValue - position.sizeInUsd().toInt256() : position.sizeInUsd().toInt256() - cache.positionValue;
        cache.uncappedTotalPositionPnl = cache.totalPositionPnl;

        if (cache.totalPositionPnl > 0) {
            cache.pnlToken = position.isLong() ? market.longToken : market.shortToken;
            cache.poolTokenAmount = MarketUtils.getPoolAmount(dataStore, market, cache.pnlToken);
            cache.poolTokenPrice = position.isLong() ? prices.longTokenPrice.min : prices.shortTokenPrice.min;
            cache.poolTokenUsd = cache.poolTokenAmount * cache.poolTokenPrice;
            cache.poolPnl = MarketUtils.getPnl(
                dataStore,
                market,
                prices.indexTokenPrice,
                position.isLong(),
                true
            );

            cache.cappedPoolPnl = MarketUtils.getCappedPnl(
                dataStore,
                market.marketToken,
                position.isLong(),
                cache.poolPnl,
                cache.poolTokenUsd,
                Keys.MAX_PNL_FACTOR_FOR_TRADERS
            );

            if (cache.cappedPoolPnl != cache.poolPnl && cache.cappedPoolPnl > 0 && cache.poolPnl > 0) {
                cache.totalPositionPnl = Precision.mulDiv(cache.totalPositionPnl.toUint256(), cache.cappedPoolPnl, cache.poolPnl.toUint256());
            }
        }

@>      if (position.sizeInUsd() == sizeDeltaUsd) {
            cache.sizeDeltaInTokens = position.sizeInTokens();
        } else {
            if (position.isLong()) {
                cache.sizeDeltaInTokens = Calc.roundUpDivision(position.sizeInTokens() * sizeDeltaUsd, position.sizeInUsd());
            } else {
                cache.sizeDeltaInTokens = position.sizeInTokens() * sizeDeltaUsd / position.sizeInUsd();
            }
        }

@>      cache.positionPnlUsd = Precision.mulDiv(cache.totalPositionPnl, cache.sizeDeltaInTokens, position.sizeInTokens()); 
        //sizeDeltaInTokens == sizeInTokens()
        cache.uncappedPositionPnlUsd = Precision.mulDiv(cache.uncappedTotalPositionPnl, cache.sizeDeltaInTokens, position.sizeInTokens());

        return (cache.positionPnlUsd, cache.uncappedPositionPnlUsd, cache.sizeDeltaInTokens);
    }
```

Here the function calculates the totalPnl and calculate what percentage of the PNL to return based on sizeDeltaInUsd the caller inputted. However, since sizeDeltaInUsd was set to the position's sizeDeltaInUsd due to the `usePositionSizeAsSizeDeltaUsd` being true, this makes the function returns the totalPnl.

When the position is in loss and total PNL of the position is larger than the user's collateral amount(user has a few percentage of the vault + position is in loss), this negative PNL value which will be deducted from the collateral amount of the user in \_withdraw() will cause an underflow revert.

## Impact

Users may not be able to withdraw due to underflow revert or take on the loss of the whole position.

## Tools Used

Manual Review

## Recommendations

Pass in `false` for `usePositionSizeAsSizeDeltaUsd` in gmxReader.getPositionInfo().

## <a id='H-05'></a>H-05. Subtracting position fee in position net value will lead to incorrect share allocation

_Submitted by [vinica_boy](https://profiles.cyfrin.io/u/vinica_boy)._      
            


## Summary

In order to calculate how much shares should be minted per user deposit, we need to get the net value of the position and calculate shares proportional of the user deposit (actual increase of position). Removing the position fee in the calculation of net value is not correct and will lead to unfair shares distribution.

## Vulnerability Details

Shares for user deposit are calculated in `PerpetualVault::_mint()`:
`_shares = amount * totalShares / totalAmountBefore;`

where `totalAmountBefore` is calculated as:
`totalAmountBefore = _totalAmount(prices) - amount;`

```solidity
  function _totalAmount(MarketPrices memory prices) internal view returns (uint256) {
    if (positionIsClosed) {
      return collateralToken.balanceOf(address(this));
    } else {
      IVaultReader.PositionData memory positionData = vaultReader.getPositionInfo(curPositionKey, prices);
      uint256 total = IERC20(indexToken).balanceOf(address(this)) * prices.indexTokenPrice.min / prices.shortTokenPrice.min
          + collateralToken.balanceOf(address(this))
          + positionData.netValue / prices.shortTokenPrice.min;

      return total;
    }
  }
```

In `VaultReader::getPositionInfo()` we have the following to get the `netValue`:

```solidity
 uint256 netValue = 
      positionInfo.position.numbers.collateralAmount * prices.shortTokenPrice.min +
      positionInfo.fees.funding.claimableLongTokenAmount * prices.longTokenPrice.min +
      positionInfo.fees.funding.claimableShortTokenAmount * prices.shortTokenPrice.min -
      positionInfo.fees.borrowing.borrowingFeeUsd -
      positionInfo.fees.funding.fundingFeeAmount * prices.shortTokenPrice.min -
      positionInfo.fees.positionFeeAmount * prices.shortTokenPrice.min;
    
    if (positionInfo.basePnlUsd >= 0) {
      netValue = netValue + uint256(positionInfo.basePnlUsd);
    } else {
      netValue = netValue - uint256(-positionInfo.basePnlUsd);
    }
```

We have already adjusted user's actual increase of position in `afterOrderExecution()`:

```soldity
if (flow == FLOW.DEPOSIT) {
        uint256 amount = depositInfo[counter].amount;
        uint256 feeAmount = vaultReader.getPositionFeeUsd(market, orderResultData.sizeDeltaUsd, false) / prices.shortTokenPrice.min;
        uint256 prevSizeInTokens = flowData;
        int256 priceImpact = vaultReader.getPriceImpactInCollateral(curPositionKey, orderResultData.sizeDeltaUsd, prevSizeInTokens, prices);
        uint256 increased;
        if (priceImpact > 0) {
          increased = amount - feeAmount - uint256(priceImpact) - 1;
        } else {
          increased = amount - feeAmount + uint256(-priceImpact) - 1;
        }
        _mint(counter, increased, false, prices);
        nextAction.selector = NextActionSelector.FINALIZE;
      } else {
        _updateState(false, orderResultData.isLong);
      }
```

Removing the position fee from the netValue of a position would result in better shares allocation for late depositors. Position fee should not be accounted in the net value as it is taken from increase/decrease amounts in GMX and fee is static percent of the position size.

Consider the following example (for the purpose of example, we can consider that there is not a borrowing/funding fee and price of index token between to increase operations is the same):

* We have a position with \$1000 collateral and \$3000 position size in USD. Lets say position fee is 0.33% (it is calculated based on position size) and we have 1000e14 total shares (1000e6 \* 1e8)
* Alice deposits \$1000 worth of collateral and gets `1000e6 * totalShares / 1000e6 - (positionFee)` shares which is equal to `1000e6 * 1000e14 / 1000e6 - 10e6` which makes `99999999990000000` shares
* Bob deposits \$1000 shares right after Alice and since price of index token is the same and there are no funding/borrowing fees, Bob is expected to get the same amount of shares.
* Calculating Bob's shares we got `1000e6 * (1000e14 + Alice's shares)/ (1000e6 + Alice's increase - positionFee)` which is equal to `1000e6 * (1000e14 + 99999999990000000) / uint(1990e6 - 20e6)` which makes `101522842634517766`
* Every consecutive depositor will be getting more and more shares than what is fair.

## Impact

Incorrect shares allocation.

## Tools Used

Manual review.

## Recommendations

Do not use positionFee when calculating netValue of a position.


# Medium Risk Findings

## <a id='M-01'></a>M-01. Wrong index causes last depositor to always get execution fee refund if cancelFlow is called by keeper to cancel a withdrawal

_Submitted by [anchabadze](https://profiles.cyfrin.io/u/anchabadze), [riceee](https://profiles.cyfrin.io/u/riceee), [cipherhawk](https://profiles.cyfrin.io/u/cipherhawk), [bigsam](https://profiles.cyfrin.io/u/bigsam), [0xkyosi](https://profiles.cyfrin.io/u/0xkyosi), [den_dokka](https://profiles.cyfrin.io/u/den_dokka), [leogold](https://profiles.cyfrin.io/u/leogold), [sauronsol](https://profiles.cyfrin.io/u/sauronsol), [0xrststn](https://profiles.cyfrin.io/u/0xrststn), [dhank](https://profiles.cyfrin.io/u/dhank), [TheKhans](https://codehawks.cyfrin.io/team/cm4wn0h6l0001gtwtt8yx45gt). Selected submission by: [den_dokka](https://profiles.cyfrin.io/u/den_dokka)._      
            


## Summary

The function `PerpetualVault:cancelFlow:L419-422`, can be called by the keeper to cancel the current flow. It will call the internal `PerpetualVault:_cancelFlow:L1220-1242` function, which refunds the execution fee paid by the user who initialized the (latest) flow, now being canceled. The refund is being done by calling `refundExecutionFee` on the `GmxProxy` contract, using `depositInfo[counter].owner` and `depositInfo[counter].executionFee` as arguments. This will correctly identify the user in the case of a deposit, as the counter state will always be the index of the latest depositor. However, it will most likely be incorrect if the flow being canceled is a withdrawal, since the withdrawer’s index in the `depositInfo` mapping will not equal the current counter value unless they were also the latest depositor. If the withdrawal being canceled does not belong to the latest depositor, the user who was the last depositor will have their execution fee refunded instead. This will continue to happen each time a flow is canceled, meaning the lastest depositor can have their fee refunded many times over, while  the withdrawers will not receive any refund.

## Vulnerability Details

The state variable `depositInfo` is used to track deposits.
The state variable `counter` in  `PerpetualVault:L94` increments each time a deposit is done, and when used to index the `depositInfo` mapping it will always reference the latest entry in the mapping/the last depositor.

```Solidity
    //PerpetualVault L87-88  state variables
    uint256 counter;
    mapping(uint256 => DepositInfo) public depositInfo;
```

```Solidity
    //PerpetualVault:deposit:L228 
    counter++;
```

`_cancelFlow` function contains the flawed code for handling the cancellation of a withdrawal flow:

```Solidity
        //PerpetualVault:_cancelFlow:L1220-1242
        } else if (flow == FLOW.WITHDRAW) {
            try
                IGmxProxy(gmxProxy).refundExecutionFee(
@>                    depositInfo[counter].owner,          
@>                    depositInfo[counter].executionFee
                )
            {} catch {}
        }
```

The same arguments for `refundExecutionFee` are used both for canceling deposits and if the flow is a withdrawal.
This will be correct for the deposit case, and if the user currently withdrawing also made the last deposit.
If this is not the case, the data at index counter will belong to another user, and the `refundExecutionFee` function will refund them, and the withdrawer will get no refund.

## POC

Add this code to `test/PerpetualVault.t.sol` as it uses fixtures from that file.

```Solidity
    //using 2x vault as natspec states cancelflow should not be called for 1x long vaults
    function test_Refund_Withdrawal_On_Cancel() external {
        uint256 collateralTokensUsed = 1e10;

        //Bob deposit
        address bob = makeAddr("bob");
        payable(bob).transfer(1 ether);
        depositFixtureInto2x(bob, collateralTokensUsed);

        //open short position in vault
        MarketPrices memory prices = mockData.getMarketPrices();
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encode(3380000000000000);
        address keeper = PerpetualVault(vault2x).keeper();
        vm.prank(keeper);
        PerpetualVault(vault2x).run(true, false, prices, data);
        GmxOrderExecuted2x(true);

        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, data);

        //Alice deposit
        address alice = makeAddr("alice");
        payable(alice).transfer(1 ether);
        depositFixtureInto2x(alice, collateralTokensUsed);

        //increase position in vault
        data[0] = abi.encode(3380000000000000);
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, data);
        GmxOrderExecuted2x(true);
        vm.prank(keeper);

        // finalize deposit
        (PerpetualVault.NextActionSelector selector, ) = PerpetualVault(vault2x)
            .nextAction();
        assertEq(uint8(selector), 6);
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, data);

        //eve deposit while active position and pays exection fee
        address eve = makeAddr("eve");
        payable(eve).transfer(1 ether);
        depositFixtureInto2x(eve, collateralTokensUsed);

        //finish deposit and increase position
        data[0] = abi.encode(3380000000000000);
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, data);
        GmxOrderExecuted2x(true);

        // finalize deposit
        (selector, ) = PerpetualVault(vault2x).nextAction();
        assertEq(uint8(selector), 6);
        delete data;
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, data);

        //skip locktime
        uint256 lockTime = 1;
        PerpetualVault(vault2x).setLockTime(lockTime);
        vm.warp(block.timestamp + lockTime + 1);

        //No next action and flow is none
        (selector, ) = PerpetualVault(vault2x).nextAction();
        assertEq(uint8(selector), 0);
        uint8 flow = uint8(PerpetualVault(vault2x).flow());
        assertEq(flow, 0);

        //get user deposit for bob and withdraw
        uint256[] memory depositIds = PerpetualVault(vault2x).getUserDeposits(
            bob
        );
        uint256 executionFee = PerpetualVault(vault2x).getExecutionGasLimit(
            false
        );
        vm.deal(bob, 1 ether);
        vm.prank(bob);
        // bob withdraws with executionFee
        PerpetualVault(vault2x).withdraw{value: executionFee * tx.gasprice}(
            bob,
            depositIds[0]
        );

        //asert flow is now withdraw
        flow = uint8(PerpetualVault(vault2x).flow());
        assertEq(flow, 3);

        GmxOrderExecuted2x(true);

        //balance of users before cancelling flow
        uint256 eveBalanceBefore = eve.balance;
        uint256 bobBalanceBefore = bob.balance;

        //keeper cancels bobs withdrawal
        vm.prank(keeper);
        PerpetualVault(vault2x).cancelFlow();

        //eve as the last depositor should have unchanged eth balance
        //and since bob's withdrawal was canceled he should have increased due to the refund
        assertTrue(eveBalanceBefore == eve.balance);            //these will fail
        assertTrue(bobBalanceBefore < bob.balance);
    }
```

## Impact

Paid executionFees will be refunded to the wrong user. This is likely to happen frequently if `cancelFlow` is called regularly. While the NatSpec for `cancelFlow` states this should only be done for GMX positions, there is nothing stopping this from being done to vaults that have used DEX swaps (ParaSwap). If DEX swaps are used frequently by the keeper,\
it could incentivize depositors to pay very large executionFees. This is because the fee will be repaid on deposit if only a DEX swap is used. And being the latest depositor with a large `depositInfo[counter].executionFee` would mean\
getting repaid that amount every time a withdrawal is canceled.

## Tools Used

Manual review

## Recommendations

In `withdraw` function at the start of a withdrawal flow the state variable `flowData` is set to the depositId of the withdrawal.

```Solidity
    //PerpetualVault:withdraw:L256
    flowData = depositId;
```

This can be used in `PerpetualVault:_cancelFlow:L1220-1242` to get the correct index for `depositInfo` mapping.

```diff
        // _cancelFlow L1231
        } else if (flow == FLOW.WITHDRAW) {
+           (uint256 depositId) = flowData;
            try
                IGmxProxy(gmxProxy).refundExecutionFee(
-                    depositInfo[counter].owner,
-                    depositInfo[counter].executionFee
+                    depositInfo[depositId].owner,
+                    depositInfo[depositId].executionFee
                )
            {} catch {}
        }
```

## <a id='M-02'></a>M-02. PerpetualVault can be completely bricked

_Submitted by [izuman](https://profiles.cyfrin.io/u/izuman), [vinica_boy](https://profiles.cyfrin.io/u/vinica_boy), [0xl33](https://profiles.cyfrin.io/u/0xl33), [0xVI](https://codehawks.cyfrin.io/team/cm7ipvqj60011126cknfq16hk), [mrkaplan](https://profiles.cyfrin.io/u/mrkaplan), [wellbyt3](https://profiles.cyfrin.io/u/wellbyt3), [ChainDefenders](https://codehawks.cyfrin.io/team/cm2bxupf00003grinaqv78qfm), [harry_cryptodev](https://profiles.cyfrin.io/u/harry_cryptodev), [royalmanbiz](https://profiles.cyfrin.io/u/royalmanbiz), [kirkeelee](https://profiles.cyfrin.io/u/kirkeelee), [bladesec](https://profiles.cyfrin.io/u/bladesec). Selected submission by: [0xVI](https://codehawks.cyfrin.io/team/cm7ipvqj60011126cknfq16hk)._      
            


## Summary

According to the GMX integration notes, there is a possibility that two handlers may temporarily exist at the same time. As a result, the callback contract must be able to accept calls from multiple handlers. However, the `gmxProxy` contract does not implement this functionality to whitelist multiple handlers, leading to a critical issue. This limitation can severely impact the vault, potentially rendering it completely inoperable.

## Vulnerability Details

According to the [GMX integration notes](https://github.com/gmx-io/gmx-synthetics?tab=readme-ov-file#integration-notes), points 8 and 9 state:

> When creating a callback contract, the callback contract may need to whitelist the DepositHandler, OrderHandler, or WithdrawalHandler. It should be noted that new versions of these handlers may be deployed as new code is added to the handlers. Additionally, it is possible for two handlers to temporarily exist at the same time, e.g., OrderHandler(1) and OrderHandler(2). Due to this, the callback contract should be able to whitelist and simultaneously accept callbacks from multiple DepositHandlers, OrderHandlers, and WithdrawalHandlers.

From this, it is evident that multiple OrderHandlers may coexist temporarily. However, the `gmxProxy` contract currently supports only a single handler at a time, as shown in the `validCallback` modifier:

```solidity
modifier validCallback(bytes32 key, Order.Props memory order) {
    require(
        msg.sender == address(orderHandler) ||
            msg.sender == address(liquidationHandler) ||
            msg.sender == address(adlHandler),
        "invalid caller"
    );
    require(order.addresses.account == address(this), "not mine");
    _;
}
```

While the `updateGmxAddresses()` function allows updating handler addresses, it does not account for scenarios where multiple handlers exist simultaneously. This limitation could lead to critical issues.

Consider the following scenario:

1. The `PerpetualVault` opens a long/short position on GMX V2.
2. Bob deposits 100 collateral tokens into the vault, triggering the creation of a `MarketIncrease` order to increase the position.
3. The keeper calls `runNextAction`, which successfully creates the order on GMX V2.
4. The GMX V2 keeper subsequently executes the order.
5. At this point, assume that two OrderHandlers exist: `OrderHandler(1)` and `OrderHandler(2)`, but the `gmxProxy` contract only accepts callbacks from `OrderHandler(1)`.
6. If `OrderHandler(2)` attempts to call `afterOrderExecution`, the transaction will revert, preventing the necessary state updates in the vault.

Since GMX V2 executes orders using a `try/catch` block, the order will be executed on GMX V2, and Bob’s funds will be transferred to the GMX V2 vault’s position. However, because the callback was never executed, the vault's state remains inconsistent:

* The `FLOW` state remains in `DEPOSIT`, preventing further deposits.
* Bob does not receive any shares.
* If the keeper attempts to call `cancelFlow`, it will revert due to `_gmxLock == true`:

```solidity
modifier gmxLock() {
    if (_gmxLock == true) {
        revert Error.GmxLock();
    }
    _;
}
```

Because `FLOW` remains stuck in `DEPOSIT`, no further deposits will be possible:

```solidity
function deposit(uint256 amount) external payable nonReentrant {
    _noneFlow();
    ...
}

function _noneFlow() internal view {
    if (flow != FLOW.NONE) {
        revert Error.FlowInProgress();
    }
}
```

Additionally, attempts to cancel the flow will fail:

```solidity
function cancelFlow() external nonReentrant gmxLock {
    _onlyKeeper();
    _cancelFlow();
}
```

`POC :`

To run the test in `PerpetualVault.t.sol`, use:

```solidity
forge test --mt testHandlersError --fork-url  <ARBITRUM_RPC_URL> --via-ir -vvvv

```

```solidity

function testHandlersError() external {
    IERC20 collateralToken = PerpetualVault(vault).collateralToken();
    address bob = makeAddr("bob");
    uint256 amount = 1e10;
    vm.startPrank(bob);
    deal(address(collateralToken), bob, amount);
    uint256 executionFee = PerpetualVault(vault).getExecutionGasLimit(true);
    collateralToken.approve(vault, amount*3);
    PerpetualVault(vault).deposit{value: executionFee * tx.gasprice}(amount);
    vm.stopPrank();

    MarketPrices memory prices = mockData.getMarketPrices();
    bytes[] memory data = new bytes[](2);
    data[0] = abi.encode(3380000000000000);
    address keeper = PerpetualVault(vault).keeper();
    vm.startPrank(keeper);
    PerpetualVault(vault).run(true, false, prices, data);
    vm.stopPrank();

    address gmxProxy = address(PerpetualVault(vault).gmxProxy());
    address gmxOwner = GmxProxy(payable(gmxProxy)).owner();

    // taken from setup
    address ethUsdcMarket = address(0x70d95587d40A2caf56bd97485aB3Eec10Bee6336);
    address orderHandler = address(0xe68CAAACdf6439628DFD2fe624847602991A31eB);
    // old address orderHandler = address(0xB0Fc2a48b873da40e7bc25658e5E6137616AC2Ee);
    address liquidationHandler = address(0xdAb9bA9e3a301CCb353f18B4C8542BA2149E4010);
    // old address liquidationHandler = address(0x08A902113F7F41a8658eBB1175f9c847bf4fB9D8);
    address adlHandler = address(0x9242FbED25700e82aE26ae319BCf68E9C508451c);
    // old address adlHandler = address(0x26BC03c944A4800299B4bdfB5EdCE314dD497511);
    address gExchangeRouter = address(0x900173A66dbD345006C51fA35fA3aB760FcD843b);
    // old address gExchangeRouter = address(0x69C527fC77291722b52649E45c838e41be8Bf5d5);
    address gmxRouter = address(0x7452c558d45f8afC8c83dAe62C3f8A5BE19c71f6);
    address dataStore = address(0xFD70de6b91282D8017aA4E741e9Ae325CAb992d8);
    address orderVault = address(0x31eF83a530Fde1B38EE9A18093A333D8Bbbc40D5);
    address gmxReader = address(0x0537C767cDAC0726c76Bb89e92904fe28fd02fE1);
    // address gmxReader = address(0x5Ca84c34a381434786738735265b9f3FD814b824);
    address referralStorage= address(0xe6fab3F0c7199b0d34d7FbE83394fc0e0D06e99d);
    address orderHandler2 = makeAddr("orderHandler2");

    vm.startPrank(gmxOwner);
    GmxProxy(payable(gmxProxy)).updateGmxAddresses(
      orderHandler2,
      liquidationHandler,
      adlHandler,
      gExchangeRouter,
      gmxRouter,
      dataStore,
      orderVault,
      gmxReader,
      referralStorage
    );
    vm.stopPrank();
    

    (bytes32 requestKey, ) = GmxProxy(payable(gmxProxy)).queue();
    MockData.OracleSetPriceParams memory params = mockData.getOracleParams();
    address gmxKeeper = address(0x6A2B3A13be0c723674BCfd722d4e133b3f356e05);
    vm.prank(gmxKeeper);
    IOrderHandler(orderHandler).executeOrder(requestKey, params);
    
    vm.startPrank(keeper);
    PerpetualVault(vault).cancelFlow();
    vm.stopPrank();

    
  }
```

`Logs :`

```solidity

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 49.97ms (37.03ms CPU time)

Ran 1 test suite in 4.02s (49.97ms CPU time): 0 tests passed, 1 failed, 0 skipped (1 total tests)

Failing tests:
Encountered 1 failing test in test/PerpetualVault.t.sol:PerpetualVaultTest
[FAIL: GmxLock()] testHandlersError() (gas: 4905177)

Encountered a total of 1 failing tests, 0 tests succeeded
```

## Impact

Vault will be completely bricked
Loss of user funds
DOS for the users

## Tools Used

Manual review

## Recommendations

According to GMX integration note

`a possible solution would be to validate the role of the msg.sender in the RoleStore, e.g. RoleStore.hasRole(msg.sender, Role.CONTROLLER), this would check that the msg.sender is a valid handler`

## <a id='M-03'></a>M-03. getExecutionGasLimit() reports a lower gas limit due to gasPerSwap miscalculation

_Submitted by [efccweb3](https://profiles.cyfrin.io/u/efccweb3), [t0x1c](https://profiles.cyfrin.io/u/t0x1c), [vinica_boy](https://profiles.cyfrin.io/u/vinica_boy), [ChainDefenders](https://codehawks.cyfrin.io/team/cm2bxupf00003grinaqv78qfm), [mrkaplan](https://profiles.cyfrin.io/u/mrkaplan), [0xffchain](https://profiles.cyfrin.io/u/0xffchain). Selected submission by: [t0x1c](https://profiles.cyfrin.io/u/t0x1c)._      
            


## Description

When a user calls `deposit()` or `withdraw()`, these functions internally call: `_payExecutionFee --> PerpetualVault::getExecutionGasLimit() --> GmxProxy::getExecutionGasLimit()`. The function [getExecutionGasLimit()](https://github.com/CodeHawks-Contests/2025-02-gamma/blob/main/contracts/GmxProxy.sol#L169) in `GmxProxy.sol` fetches `gasPerSwap` correctly as:

```solidity
    uint256 gasPerSwap = dataStore.getUint(SINGLE_SWAP_GAS_LIMIT);
```

but then assumes the swapPath length to be `1` & never bothers to multiply it with the correct swap hops.

Let's have a look at the GMX implementation. We can see [here](https://github.com/gmx-io/gmx-synthetics/blob/b8fb11349eb59ae48a1834c239669d4ad63a38b5/contracts/data/Keys.sol#L603-L605) that `SINGLE_SWAP_GAS_LIMIT` key is retuned by the `singleSwapGasLimitKey()` function.

```solidity
    // @dev key for single swap gas limit
    // @return key for single swap gas limit
    function singleSwapGasLimitKey() internal pure returns (bytes32) {
        return SINGLE_SWAP_GAS_LIMIT;
    }
```

We can also see that a function like `estimateExecuteDecreaseOrderGasLimit()` (among many others) calculates the gas limit in the [following manner](https://github.com/gmx-io/gmx-synthetics/blob/b8fb11349eb59ae48a1834c239669d4ad63a38b5/contracts/gas/GasUtils.sol#L325-L333):

```solidity
    // @dev the estimated gas limit for decrease orders
    // @param dataStore DataStore
    // @param order the order to estimate the gas limit for
    function estimateExecuteDecreaseOrderGasLimit(DataStore dataStore, Order.Props memory order) internal view returns (uint256) {
        uint256 gasPerSwap = dataStore.getUint(Keys.singleSwapGasLimitKey());
        uint256 swapCount = order.swapPath().length;
        if (order.decreasePositionSwapType() != Order.DecreasePositionSwapType.NoSwap) {
            swapCount += 1;
        }

@--->   return dataStore.getUint(Keys.decreaseOrderGasLimitKey()) + gasPerSwap * swapCount + order.callbackGasLimit();
    }
```

Notice the `gasPerSwap * swapCount` term in the `return` statement. The Gamma implementation misses this or assumes that tokens like WBTC or LINK on both Arbitrum and Avalanche chains will be swappable with WETH in one hop, which is not necessarily true and GMX may use an optimized swap path with more than one hops.

## Impact

User may end up paying less than required execution fee and the Keepers end up paying additional amount from their own pockets.

As the contest page specifies for Depositors:

> Must provide sufficient execution fees for operations

## Recommendation

Either fetch the swapPath hops from GMX and multiply that to `gasPerSwap` OR increase the buffer on top of the calculated gas limit to stay in the safe zone.

## <a id='M-04'></a>M-04. Functions that rely on chainlink prices cannot be queried on avalanche due to sequencer uptime check.

_Submitted by [anchabadze](https://profiles.cyfrin.io/u/anchabadze), [ashishlach](https://profiles.cyfrin.io/u/ashishlach), [crmx_lom](https://profiles.cyfrin.io/u/crmx_lom), [bigsam](https://profiles.cyfrin.io/u/bigsam), [krisrenzo](https://profiles.cyfrin.io/u/krisrenzo), [y4y](https://profiles.cyfrin.io/u/y4y), [vinica_boy](https://profiles.cyfrin.io/u/vinica_boy), [inh3l](https://profiles.cyfrin.io/u/inh3l), [victorzsh](https://profiles.cyfrin.io/u/victorzsh), [codexbugmenot](https://profiles.cyfrin.io/u/codexbugmenot), [josh4324](https://profiles.cyfrin.io/u/josh4324), [wellbyt3](https://profiles.cyfrin.io/u/wellbyt3), [0xstuart](https://profiles.cyfrin.io/u/0xstuart), [ChainDefenders](https://codehawks.cyfrin.io/team/cm2bxupf00003grinaqv78qfm), [rokinot](https://profiles.cyfrin.io/u/rokinot), [pkqs90](https://profiles.cyfrin.io/u/pkqs90), [0xshoonya](https://profiles.cyfrin.io/u/0xshoonya). Selected submission by: [inh3l](https://profiles.cyfrin.io/u/inh3l)._      
            


### Summary

[Avalanche](https://docs.chain.link/data-feeds/price-feeds/addresses/?network=avalanche\&page=1) unlike [Arbitrum](https://docs.chain.link/data-feeds/price-feeds/addresses/?network=arbitrum\&page=1) needs no sequencer uptime check. As a result, checking for uptime feeds when validating price will cause the function to always revert.

Also, the `sequencerUptimeFeed` address is hardcoded to an address specific only to arbitrum.

### Vulnerability Details

In KeeperProxy.sol, `_validatePrice` [performs](https://github.com/CodeHawks-Contests/2025-02-gamma/blob/e5b98627a4c965e203dbb616a5f43ec194e7631a/contracts/KeeperProxy.sol#L152-L166) an L2 sequencer check. This check will break on avalanche, as the chain doesn't have a sequencer, or require a sequencer check.

```solidity
  function _validatePrice(address perpVault, MarketPrices memory prices) internal view {
>   // L2 Sequencer check
    (
      /*uint80 roundID*/,
      int256 answer,
      uint256 startedAt,
      /*uint256 updatedAt*/,
      /*uint80 answeredInRound*/
    ) = AggregatorV2V3Interface(sequencerUptimeFeed).latestRoundData();
    bool isSequencerUp = answer == 0;
    require(isSequencerUp, "sequencer is down");
    // Make sure the grace period has passed after the sequencer is back up.
    uint256 timeSinceUp = block.timestamp - startedAt;
    require(timeSinceUp > GRACE_PERIOD_TIME, "Grace period is not over");

    address market = IPerpetualVault(perpVault).market();
    IVaultReader reader = IPerpetualVault(perpVault).vaultReader();
    MarketProps memory marketData = reader.getMarket(market);
    
    _check(marketData.indexToken, prices.indexTokenPrice.min);
    _check(marketData.indexToken, prices.indexTokenPrice.max);
    _check(marketData.longToken, prices.indexTokenPrice.min);
    _check(marketData.longToken, prices.indexTokenPrice.max);
    _check(marketData.shortToken, prices.shortTokenPrice.min);
    _check(marketData.shortToken, prices.shortTokenPrice.max);
  }
```

Doing this regardless of whatever `sequencerUptimeFeed` is set will cause the function to always revert (even if none is set).

Also, when KeeperProxy.sol is [initialized](https://github.com/CodeHawks-Contests/2025-02-gamma/blob/e5b98627a4c965e203dbb616a5f43ec194e7631a/contracts/KeeperProxy.sol#L46-L48), the `sequencerUptimeFeed` is hardcoded to `0xFdB631F5EE196F0ed6FAa767959853A9F217697D`. On arbitrum, this is the correct address, but on avalanche, the address is [non-existent](https://avascan.info/blockchain/all/address/0xFdB631F5EE196F0ed6FAa767959853A9F217697D).

```solidity
  function initialize() external initializer {
    __Ownable2Step_init();
>   sequencerUptimeFeed = AggregatorV2V3Interface(0xFdB631F5EE196F0ed6FAa767959853A9F217697D);
```

### Impact

As a result, `_validatePrice` and all of its dependent functions, e.g [`run`](https://github.com/CodeHawks-Contests/2025-02-gamma/blob/e5b98627a4c965e203dbb616a5f43ec194e7631a/contracts/KeeperProxy.sol#L67), [`runNextAction`](https://github.com/CodeHawks-Contests/2025-02-gamma/blob/e5b98627a4c965e203dbb616a5f43ec194e7631a/contracts/KeeperProxy.sol#L79) will always fail upon deployment to avalanche.

### Tools Used

Manual Review

### Recommendations

Introduce a check for chainId in the `_validatePrice` function, if chainId is that of avalanche, skip the sequencer check.

## <a id='M-05'></a>M-05. Incorrect Share Accounting After Liquidation Leading to Ownership Dilution

_Submitted by [codexbugmenot](https://profiles.cyfrin.io/u/codexbugmenot), [harry_cryptodev](https://profiles.cyfrin.io/u/harry_cryptodev). Selected submission by: [harry_cryptodev](https://profiles.cyfrin.io/u/harry_cryptodev)._      
            


## Summary

The `PerpetualVault` contract incorrectly handles share accounting after a liquidation event when a new user deposits funds. Existing users’ shares remain unchanged despite the vault’s value dropping to zero, causing the new user’s ownership to be unfairly diluted. This results in an inaccurate distribution of vault ownership, violating the principle that a new depositor should own 100% of a vault with no prior value. &#x20;

## Vulnerability Details

In the `_mint` function, shares are calculated for a new depositor as follows: &#x20;

```Solidity
uint256 _shares;
if (totalShares == 0) {
    _shares = depositInfo[depositId].amount * 1e8;
} else {
    uint256 totalAmountBefore = _totalAmount(prices) - amount;
    if (totalAmountBefore == 0) totalAmountBefore = 1;  // Avoid division by zero
    _shares = amount * totalShares / totalAmountBefore;
}
totalShares = totalShares + _shares;
```

After liquidation: &#x20;

* `totalAmountBefore` (vault value before the deposit) is 0 because all value was lost. &#x20;
* Existing users collectively own `totalShares = A` shares, unchanged from pre-liquidation. &#x20;
* When a new user deposits amount: &#x20;

  * `totalAmountBefore` is set to 1. &#x20;
  * `_shares = amount * A / 1 = amount * A`. &#x20;
  * New `totalShares = A + (amount * A) = A(1 + amount)`.
* Ownership: &#x20;

  * Existing users: `A / [A(1 + amount)]`. &#x20;
  * New user: `(amount * A) / [A(1 + amount)] = amount / (1 + amount)`.\
    For example, if `amount = 1`:
* New user owns 50% (`1 / (1 + 1) = 0.5`). &#x20;
* Existing users own 50%.\
  This is incorrect because the new user, contributing all value post-liquidation, should own 100% of the vault—not have their ownership diluted by worthless pre-liquidation shares.

## Impact

* Ownership Dilution: The new depositor’s ownership is unfairly reduced (e.g., to 50% instead of 100%), despite contributing all post-liquidation value. &#x20;
* Financial Inaccuracy: Existing users retain ownership over a vault they no longer have value in, potentially allowing them to claim future profits they don’t deserve. &#x20;
* User Trust Erosion: This accounting flaw could deter new users who expect fair ownership proportional to their contribution, undermining the protocol’s integrity.

## Tools Used

&#x20; Manual code review and analysis &#x20;

## Recommendations

* Reset the share system when the vault’s value is zero post-liquidation to ensure the new depositor receives 100% ownership. &#x20;

## <a id='M-06'></a>M-06. User may withdraw more than expected if ADL event happens

_Submitted by [t0x1c](https://profiles.cyfrin.io/u/t0x1c), [vinica_boy](https://profiles.cyfrin.io/u/vinica_boy), [sakshamseth5](https://profiles.cyfrin.io/u/sakshamseth5), [bigsam](https://profiles.cyfrin.io/u/bigsam), [bladesec](https://profiles.cyfrin.io/u/bladesec). Selected submission by: [t0x1c](https://profiles.cyfrin.io/u/t0x1c)._      
            


## Description

First, let's take a look at the action performed by Gamma when GMX's ADL (Automatic Deleveraging) invokes `GmxProxy.sol`'s [afterOrderExecution() callback](https://github.com/CodeHawks-Contests/2025-02-gamma/blob/main/contracts/GmxProxy.sol#L248-L258):

```solidity
    } else if (msg.sender == address(adlHandler)) {
      uint256 sizeInUsd = dataStore.getUint(keccak256(abi.encode(positionKey, SIZE_IN_USD)));
      if (eventData.uintItems.items[0].value > 0) {
@-->    IERC20(eventData.addressItems.items[0].value).safeTransfer(perpVault, eventData.uintItems.items[0].value);
      }
      if (eventData.uintItems.items[1].value > 0) {
@-->    IERC20(eventData.addressItems.items[1].value).safeTransfer(perpVault, eventData.uintItems.items[1].value);
      }
@-->  if (sizeInUsd == 0) {
        IPerpetualVault(perpVault).afterLiquidationExecution();
      }
```

Any collateral & index tokens received from GMX are transferred to the PerpetualVault. And if this ADL has not resulted in the entire position size to be de-leveraged i.e. `sizeInUsd > 0`, then `afterLiquidationExecution()` is NOT called.

With that in mind, let's now look at a user's withdrawal flow:

1. User calls `withdraw()`. This sets `flow = FLOW.WITHDRAW`.
2. If there's an open position, calls `_settle()` which creates a GMX order.
3. GMX executes the settle order, triggering `afterOrderExecution()`. This sets `nextAction = NextActionSelector.WITHDRAW_ACTION`.
4. Keeper calls `runNextAction()` which if needed, swaps any indexTokens to collateralTokens.
5. Calls `_withdraw()` which creates a GMX decrease position order.
6. GMX executes decrease order, triggering `afterOrderExecution()`. This sets `nextAction = NextActionSelector.FINALIZE`.
7. Keeper calls `runNextAction()` which calls `_finalize()` which calls `_handleReturn()` to process the withdrawal.

However, `_finalize()` and `_handleReturn()` rely on contract's collateral token balance to determine how much withdrawn amount is to be credited back to the user. If an ADL inadvertently happens between steps 6 and 7, i.e. Keeper's `runNextAction()` gets front-runned coincidentally in the same block (Or Keeper fails to notice the ADL event and calls `runNextAction()` anyway), then user receives more than they should:

```solidity
  function _finalize(bytes memory data) internal {
    if (flow == FLOW.WITHDRAW) {
      (uint256 prevCollateralBalance, bool positionClosed, bool refundFee) = abi.decode(data, (uint256, bool, bool));
      // @audit : collateralToken balance has already increased due to ADL, inflating the `withdrawn` figure
@->   uint256 withdrawn = collateralToken.balanceOf(address(this)) - prevCollateralBalance;
      _handleReturn(withdrawn, positionClosed, refundFee);
    } else {
      delete swapProgressData;
      delete flowData;
      delete flow;
    }
  }

  
  function _handleReturn(uint256 withdrawn, bool positionClosed, bool refundFee) internal {
    (uint256 depositId) = flowData;
    uint256 shares = depositInfo[depositId].shares;
    uint256 amount;
    if (positionClosed) {
      amount = collateralToken.balanceOf(address(this)) * shares / totalShares;
    } else {
      // @audit-info : this is correctly calculated since both collateralTokenBalance and `withdrawn` are inflated by an equal degree  
@->   uint256 balanceBeforeWithdrawal = collateralToken.balanceOf(address(this)) - withdrawn; 
      // @audit : but this results in inflated `amount` due to inflated `withdrawn`
@->   amount = withdrawn + balanceBeforeWithdrawal * shares / totalShares; 
    }
    if (amount > 0) {
@->   _transferToken(depositId, amount); // @audit : user credited more than their fair share
    }
    // ... Rest of the code
```

## Impact

* User will receive both their proportional share from the decrease order AND the ADL tokens
* This is incorrect since ADL tokens should be distributed across all position holders. Essentially, other position holders take a loss.

## Recommendation

The fix may not be quite that simple. We may need to properly track credited tokens during ADL, perhaps by having ADL tokens flow into a separate accounting bucket.

Another way _could be_ to increment `prevCollateralBalance` inside the `if (msg.sender == address(adlHandler))` branch when `afterOrderExecution()` callback happens.

## <a id='M-07'></a>M-07. ADL can result in unwrapped ETH as output which is not handled

_Submitted by [vinica_boy](https://profiles.cyfrin.io/u/vinica_boy), [kirkeelee](https://profiles.cyfrin.io/u/kirkeelee). Selected submission by: [vinica_boy](https://profiles.cyfrin.io/u/vinica_boy)._      
            


## Summary

Based on the docs and GMX V2 code, output token from ADL order can be unwrapped ETH which is not handled in the current implementation.
From <https://github.com/gmx-io/gmx-synthetics?tab=readme-ov-file#integration-notes>:

> Accounts may receive ETH for ADLs / liquidations, if the account cannot receive ETH then WETH would be sent instead

## Vulnerability Details

In `AdlUtils::createOrder()` ([reference](https://github.com/gmx-io/gmx-synthetics/blob/b8fb11349eb59ae48a1834c239669d4ad63a38b5/contracts/adl/AdlUtils.sol#L184)), we can see that `shouldUnwrapNativeToken` is set to `true`, which will result in sending the native token to the position account later in `transferOut()` ([reference](https://github.com/gmx-io/gmx-synthetics/blob/b8fb11349eb59ae48a1834c239669d4ad63a38b5/contracts/bank/Bank.sol#L50-L63)). Additionally, since `GmxProxy` implements a `receive()` functionality, it can receive ETH instead of WETH.

The following snippet in `GmxProxy.sol` aims to handle ADL scenario and send funds to `PerpetualVault`, but it does not account the scenario mentioned above.

```solidity
else if (msg.sender == address(adlHandler)) {
      uint256 sizeInUsd = dataStore.getUint(keccak256(abi.encode(positionKey, SIZE_IN_USD)));
      if (eventData.uintItems.items[0].value > 0) {
        IERC20(eventData.addressItems.items[0].value).safeTransfer(perpVault, eventData.uintItems.items[0].value);
      }
      if (eventData.uintItems.items[1].value > 0) {
        IERC20(eventData.addressItems.items[1].value).safeTransfer(perpVault, eventData.uintItems.items[1].value);
      }
      if (sizeInUsd == 0) {
        IPerpetualVault(perpVault).afterLiquidationExecution();
      }
```

## Impact

Stuck tokens + loss of funds for depositors.

## Tools Used

Manual review.

## Recommendations

Consider checking if output token is ETH and swap it to collateral token or wrap it when received so it will be swapped like it is done before every every action.

## <a id='M-08'></a>M-08. Fetching indexToken.balanceOf() will always revert for BTC market

_Submitted by [wellbyt3](https://profiles.cyfrin.io/u/wellbyt3)._      
            


## Summary
Due to the BTC/USD market returning a non-contract address as indexToken, any calls to balanceOf() in PerpetualVault.sol revert, rendering the contracts incompatible with this key GMX market.

## Vulnerability Details

When a PerpetualVault is initialized, the indexToken address is set by calling getMarket() from the GMXReader:

```solidity
// PerpetualVault.sol::initialize()
function initialize(
    address _market,
    address _keeper,
    address _treasury,
    address _gmxProxy,
    address _vaultReader,
    uint256 _minDepositAmount,
    uint256 _maxDepositAmount,
    uint256 _leverage
  ) external initializer {
...SNIP...

    MarketProps memory marketInfo = IVaultReader(_vaultReader).getMarket(market);
@>  indexToken = marketInfo.indexToken;

...SNIP...
  }

// VaultReader.sol::getMarket()
function getMarket(address market) public view returns (MarketProps memory) {
@>  return gmxReader.getMarket(address(dataStore), market);
  }
```

According to the README, these contracts should be compatible with wBTC (i.e. the BTC/USD GMX market). However, in the BTC/USD market, `marketinfo.indexToken` is not a contract, so calling `balanceOf()` will revert.

Here's the indexToken address for the BTC/USD market on Arbitrum: https://arbiscan.io/address/0x47904963fc8b2340414262125af798b9655e58cd

`indexToken.balanceOf()` is used throughout the PerpetualVault.sol contract making Gamma's implementation incompatible with this key market.

## Impact
Contracts incompatible with key GMX market.

## Tools Used
Manual review 

## Recommendations
Consider using the long token instead of the index token for these markets, however, this can cause issues if you ever want to launch on markets where the long token doesn't equal the index token.
## <a id='M-09'></a>M-09. new deposits be incorrectly rejected due to false "maxCapReached" errors.

_Submitted by [dliteofficial](https://profiles.cyfrin.io/u/dliteofficial), [dhank](https://profiles.cyfrin.io/u/dhank). Selected submission by: [dhank](https://profiles.cyfrin.io/u/dhank)._      
            


## Summary

Once the vault is completely liquidated , totalDepositAmount remains unchanged.
Even when the withdrawer(deposit) tries to withdraw , totalDepositAMount is not reduced by the depositInfo\[depositId].amount.

As a result new deposits be incorrectly rejected due to false "maxCapReached" errors.

## Vulnerability Details

When the perpetualVault is completely liquidated in such a way the collatteralToken in the position is 0 , the currPositionKey is made `0` but the position remains open. [code](https://github.com/CodeHawks-Contests/2025-02-gamma/blob/84b9da452fc84762378481fa39b4087b10bab5e0/contracts/PerpetualVault.sol#L570-L572)

```solidity
  function afterLiquidationExecution() external {
    if (msg.sender != address(gmxProxy)) {
      revert Error.InvalidCall();
    }

    depositPaused = true;
    uint256 sizeInTokens = vaultReader.getPositionSizeInTokens(curPositionKey);
    if (sizeInTokens == 0) {
      delete curPositionKey;
    }
    ....
  }
```

This allows the the vault to continue the other user Operations like `withdraw()` and also the deposit() when the owner disable the `depositPaused`.

Now when user executes withdraw , this [code](https://github.com/CodeHawks-Contests/2025-02-gamma/blob/84b9da452fc84762378481fa39b4087b10bab5e0/contracts/PerpetualVault.sol#L1102-L1104) willl get executed.

```solidity
function _withdraw(uint256 depositId, bytes memory metadata, MarketPrices memory prices) internal {
    ....
    else if (curPositionKey == bytes32(0)) {    // vault liquidated
      _handleReturn(0, true, false);
    } 
    ....
}
```

Inside the \_handleReturn() the amount to transfer is calculated as

```solidity
    else {
      uint256 balanceBeforeWithdrawal = collateralToken.balanceOf(address(this)) - withdrawn;
      amount = withdrawn + balanceBeforeWithdrawal * shares / totalShares;
    }
```

The balance of the contract would be 0 by this time.
\=> amount = 0;

As a result the fun \_transferToken() will not get executed and also the `totalDepositAmount` is never get reduced.

## Impact

The  `totalDepositAmount` will never get reduced once the vault is liquidated and users start withdrawing.
Hence it always show the incorrect value after on.

New deposits be incorrectly rejected due to false "maxCapReached" errors.

Protocol accounting becomes inaccurate, making it difficult to track actual assets under management

## Tools Used

Manual

## Recommendations

the line     ` totalDepositAmount -= depositInfo[depositId].amount;` should be put outside the transferToken() function so that it will be executed whatsoever.

Another way is to delete the `totalDepositAmount` once the vault is completely liquidated.


# Low Risk Findings

## <a id='L-01'></a>L-01. Cancelling a Flow after a Position Is Created Might Result in Inflation/Deflation of Shares

_Submitted by [typical_human](https://profiles.cyfrin.io/u/typical_human), [0xjoyboy03](https://profiles.cyfrin.io/u/0xjoyboy03), [sakshamseth5](https://profiles.cyfrin.io/u/sakshamseth5), [c4a4d65b](https://profiles.cyfrin.io/u/c4a4d65b), [krisrenzo](https://profiles.cyfrin.io/u/krisrenzo), [0xVI](https://codehawks.cyfrin.io/team/cm7ipvqj60011126cknfq16hk), [riceee](https://profiles.cyfrin.io/u/riceee), [itsgreg](https://profiles.cyfrin.io/u/itsgreg), [bladesec](https://profiles.cyfrin.io/u/bladesec), [Midgar](https://codehawks.cyfrin.io/team/clw2heqly00017hplhw9jzhzq), [TheKhans](https://codehawks.cyfrin.io/team/cm4wn0h6l0001gtwtt8yx45gt). Selected submission by: [riceee](https://profiles.cyfrin.io/u/riceee)._      
            


## Vulnerability Details

In `PerpetualVault` a deposit or withdrawal flow can be cancelled via Keepers calling the `cancelFlow` function. The `cancelFlow` has the `gmxLock` modifier meaning that `cancelFlow` can be called anytime but not when gmx order request is on-going. Before \_createIncrease/DecreasePosition and after it's executed fully.

But this could lead to situations where a flow is cancelled after a order is executed fully. And that might lead to some unintended results.

* During a deposit flow if the flow is cancelled after the execution of `_createIncreasePosition` it could result in a inflation in the value of shares if the vault has enough collateral tokens acquired form the last action. Since cancelling the flow in a situation like that would result in a refund of the user's collateral but it does not decrease the `totalShares` value. Meaning that although the user is now not a part of the vault the shares minted to them still remain in the `totalShares`. Resulting in inflation in the value of shares.
* During a withdrawal flow if the flow is cancelled after the execution of `_createDecreasePosition`, it could result in a situation where the position is not entirely closed and the vault now has the user's collateral that is to be returned plus any collateral amount resulting from the last action / settle action. But if the user calls `withdraw` again in this situation, the withdraw flow will execute resulting in another  position of the withdrawer's amount being closed from the active position, and then the amount calculated in `_handleReturn` would result in a withdrawal amount a bit higher than during the previous withdrawal flow. Because the current `balanceBeforeWithdrawal` would not only include any collateral generated from last action and settle but also the collateral withdrawn during the previously cancelled flow.

## Impact

During a deposit flow it could result in a inflation in share value  and a deflation in share value during a withdrawal flow

## PoC

### During a deposit flow, the flow of action would be something like this:

```solidity
    function test_CancelDeposit_Call_After_Pos_Increases() external {
        //setup
        address alice = makeAddr("alice");
        payable(alice).transfer(1 ether);
        depositFixture(alice, 1e12);

        MarketPrices memory prices = mockData.getMarketPrices();
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encode(3380000000000000);
        address keeper = PerpetualVault(vault).keeper();
        vm.prank(keeper);
        PerpetualVault(vault).run(true, false, prices, data);//1x SHORT 
        GmxOrderExecuted(true);
        vm.prank(keeper);
        PerpetualVault(vault).runNextAction(prices, data);
        emit log_named_decimal_uint("Vault shares before cancel flow", PerpetualVault(vault).totalShares(), 8);
        //

        //A withdraw action before the deposit action causes enough indexTokens to enter the vault due to settle/ADL action

        //Someone deposits to the open position after that 
        deal(alice, 1 ether);
        depositFixture(alice, 1e8);
        vm.prank(keeper);
        PerpetualVault(vault).runNextAction(prices, data);
        deal(address(PerpetualVault(vault).collateralToken()), vault, 1e10);//indexTokens Swapped to collateral during INCREASE_ACTION
        GmxOrderExecuted(true); //increase position completed

        (PerpetualVault.NextActionSelector selector,) = PerpetualVault(vault).nextAction();
        assertEq(uint8(selector), 6);

        bool isLock = PerpetualVault(vault).isLock();
        assertEq(isLock, false);

        uint256 ethBalBefore = alice.balance;
        //keeper calls cancelFlow after a position is executed 
        //Keeper calls cancel flow after the next deposit has already increased the position, it passes because the collateral tokens generated in vault from the last withdraw action are enough to suffice the deposit amount of the new deposit
        vm.prank(keeper);
        PerpetualVault(vault).cancelFlow();
        assertTrue(ethBalBefore < alice.balance);

        (selector,) = PerpetualVault(vault).nextAction();
        assertEq(uint8(selector), 6);
        // uint8 isNextAction = uint8(PerpetualVault(vault).isNextAction());
        // assertEq(isNextAction, 6);
        uint8 flow = uint8(PerpetualVault(vault).flow());
        assertEq(flow, 5);
        emit log_named_decimal_uint("Vault Shares after cancel flow", PerpetualVault(vault).totalShares(), 8);
    }
```

```diff
Logs:
Vault shares before cancel flow: 1000000000000.00000000
Vault Shares after cancel flow: 1000099186888.80175813
```

We notice that even though the deposit was cancelled successfully the vault generates extra shares, this would result in inflation in share value during future withdrawals since we withdraw pro-rata to the shares owned `shares / totalShares` leaving unclaimable collateral becuase of the extra deposit amount that came in even though the flow was cancelled.

### During Withdrawal flow :

```Solidity
    function test_CancelWithdraw_Call_After_Pos_Decreases() external {
        console.log("Alice Deposits to the Vault"); 
        IERC20 collateralToken = PerpetualVault(vault).collateralToken();
        address keeper = PerpetualVault(vault).keeper();
        address alice = makeAddr("alice");
        depositFixture(alice, 1e12);
        (,uint256 aliceShares,,,,) = PerpetualVault(vault).depositInfo(1);
        emit log_named_decimal_uint("Shares Minted when no pos open", aliceShares, 8);
        emit log_named_decimal_uint("Total Collateral In Vault Initially", collateralToken.balanceOf(vault), 6); 
        

        MarketPrices memory prices = mockData.getMarketPrices();
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encode(3380000000000000);
        vm.prank(keeper);
        PerpetualVault(vault).run(true, false, prices, data);//1x SHORT POSITION
        PerpetualVault.FLOW flow = PerpetualVault(vault).flow();
        assertEq(uint8(flow), 2);
        GmxOrderExecuted(true);
        vm.prank(keeper);
        PerpetualVault(vault).runNextAction(prices, new bytes[](0));

        ////Bob also deposits ///////////////////////////////////////////////
        console.log("Bob deposits during an open position");
        address bob = makeAddr("bob");
        deal(bob, 1 ether); //to cover for execution fees
        depositFixture(bob, 1e12);
        (PerpetualVault.NextActionSelector selector,) = PerpetualVault(vault).nextAction();
        assertEq(uint8(selector), 1);//INCREASE ACTION
        //keeper for nextAction call 
        vm.prank(keeper);
        PerpetualVault(vault).runNextAction(prices, data);
        GmxOrderExecuted(true);//callback
        (selector,) = PerpetualVault(vault).nextAction();
        assertEq(uint8(selector), 6);//FINALIZE ACTION
        //keeper for nextAction call 
        vm.prank(keeper);
        PerpetualVault(vault).runNextAction(prices, new bytes[](0));
        ////////////////////////////////////////////////////////////////////////////////
        //ALice Withdraws
        console.log("Alice tries to withdraw");
        uint256 balanceBeforeWithdrawal = collateralToken.balanceOf(vault);
        uint256 totalShares = PerpetualVault(vault).totalShares();
        uint256[] memory depositIds = PerpetualVault(vault).getUserDeposits(alice);
        uint256 executionFee = PerpetualVault(vault).getExecutionGasLimit(false);

        uint256 lockTime = 1;
        PerpetualVault(vault).setLockTime(lockTime);
        vm.warp(block.timestamp + lockTime + 1);
        payable(alice).transfer(1 ether);
        vm.prank(alice);
        PerpetualVault(vault).withdraw{value: executionFee * tx.gasprice}(alice, depositIds[0]);

        GmxOrderExecuted(true);//settle callback

        (selector,) = PerpetualVault(vault).nextAction();
        assertEq(uint8(selector), 3);//WITHDRAW ACTION

        bytes[] memory swapData = new bytes[](2);
        swapData[0] = abi.encode(3390000000000000);
        vm.prank(keeper);
        PerpetualVault(vault).runNextAction(prices, swapData);

        GmxOrderExecuted(true);//market decrease callback
        uint256 withdrawAmount = collateralToken.balanceOf(vault) - balanceBeforeWithdrawal;

        bool isLock = PerpetualVault(vault).isLock();
        assertEq(isLock, false);
        console.log("Keeper cancels withdraw after the market position is decreased");
        //keeper calls cancelFlow after a position is executed 
        vm.prank(keeper);
        PerpetualVault(vault).cancelFlow();
        vm.prank(keeper);
        PerpetualVault(vault).runNextAction(prices, new bytes[](0));//finalize
        //emit log_named_decimal_uint("Total Collateral In Vault When withdraw flow cancelled after pos decrased", collateralToken.balanceOf(vault), 6); 
        uint256 refundAmountInCancelFlow = withdrawAmount + balanceBeforeWithdrawal * aliceShares / totalShares;
        emit log_named_decimal_uint("Refund Amount for Alice When Flow Cancelled", refundAmountInCancelFlow, 6);       

        //Alice withdraws again since the withdraw was cancelled 
        console.log("Alice Withdraws again after her withdraw was cancelled");
        balanceBeforeWithdrawal = collateralToken.balanceOf(vault);
        vm.prank(alice);
        PerpetualVault(vault).withdraw{value: executionFee * tx.gasprice}(alice, depositIds[0]);

        GmxOrderExecuted(true);//settle callback
        (selector,) = PerpetualVault(vault).nextAction();
        assertEq(uint8(selector), 3);//WITHDRAW ACTION

        vm.prank(keeper);
        PerpetualVault(vault).runNextAction(prices, swapData);

        GmxOrderExecuted(true);//market decrease callback
        withdrawAmount = collateralToken.balanceOf(vault) - balanceBeforeWithdrawal;
        //emit log_named_decimal_uint("Total Collateral In Vault after second withdraw call", collateralToken.balanceOf(vault), 6);
        uint256 refundAmount= withdrawAmount + balanceBeforeWithdrawal * aliceShares / totalShares;
        emit log_named_decimal_uint("Refund Amount When calling Withdrawal again", refundAmount, 6);  
        vm.prank(keeper);
        PerpetualVault(vault).runNextAction(prices, new bytes[](0));//FINALIZE
    }
```

```diff
Logs:
Alice Deposits to the Vault
Shares Minted when no pos open: 1000000000000.00000000
Total Collateral In Vault Initially: 1000000.000000
Bob deposits during an open position
Alice tries to withdraw
Keeper cancels withdraw after the market position is decreased
Refund Amount for Alice When Flow Cancelled: 994108.906352
Alice Withdraws again after her withdraw was cancelled
Refund Amount When calling Withdrawal again: 995377.193831
```

Here we notice, if the withdrawal flow is cancelled after a position has been decreased, and then the withdrawer  tries to withdraw again they receive more collateral for the same amount of tokens. Resulting in deflation of share value.

## Tools Used

Manual  Review\
Foundry

## Recommendations

The only recommendation I could think of is to allow keepers to only call `cacelFlow` before `_createIncreasePosition` / `_createDecreasePosition` is executed and not after that. This could be done by adding a flag variable such as `bool positionExecuted` that keeps track of the position execution during a single flow and allowing the keepers to enter `cancelFlow` only when `positionExecuted` is `false`

#### Note :- I consider this a valid issue because it does not stem from a scenario where the keeper loses functionality or behaves maliciously. The keeper is executing its role as intended. Instead, the root cause lies in a fundamental logical flaw in how `cancelFlow` operates. This design flaw can lead to unintended consequences, regardless of the keeper's trustability (hence why the low), making it a issue that needs to be addressed.

## <a id='L-02'></a>L-02. Fees not refunded to users on position closed and funds locked/lost

_Submitted by [0xVI](https://codehawks.cyfrin.io/team/cm7ipvqj60011126cknfq16hk), [0xffchain](https://profiles.cyfrin.io/u/0xffchain), [dhank](https://profiles.cyfrin.io/u/dhank). Selected submission by: [0xffchain](https://profiles.cyfrin.io/u/0xffchain)._      
            


## Summary

User is not refunded fees when vault changes position ahead of the users transaction. 

## Vulnerability Details

When depositing into the vault, there are two mechanisms to which the deposit serves, which is dependent on if the vault has a position opened on GMX or closed.

&#x20;

```Solidity
  function deposit(uint256 amount) external nonReentrant payable {
    _noneFlow();
    if (depositPaused == true) {
      revert Error.Paused();
    }
    if (amount < minDepositAmount) {
      revert Error.InsufficientAmount();
    }
    if (totalDepositAmount + amount > maxDepositAmount) {
      revert Error.ExceedMaxDepositCap();
    }
    flow = FLOW.DEPOSIT;
    collateralToken.safeTransferFrom(msg.sender, address(this), amount);
    counter++;
    depositInfo[counter] = DepositInfo(amount, 0, msg.sender, 0, block.timestamp, address(0));
    totalDepositAmount += amount;
    EnumerableSet.add(userDeposits[msg.sender], counter);
    if (positionIsClosed) {
      MarketPrices memory prices;
      // @audit where is this guy updated?
      _mint(counter, amount, false, prices);
      _finalize(hex'');
    } else {
      _payExecutionFee(counter, true);
      // mint share token in the NextAction to involve off-chain price data and improve security
      nextAction.selector = NextActionSelector.INCREASE_ACTION;
      nextAction.data = abi.encode(beenLong);
    }
  }

```

When the vault has a position open, it collects the deposit amount and fees and saves the next action as an increase action. But when it is closed, it simply mints shares to the depositing user. The challenge here is that the user depositing does not know what state the vault will be in at execution. It could be an open position or closed position.

### POC

1. The Gamma vault X is in openPosition state.
2. Bob sends a transaction to Gamma contracts, with deposit of 100 usdc and 5 avax to pay for execution of the transaction.
3. Since bob inputs an acceptable priority fee as is required in Avax dynamic fee model
4. The keeper sends out a transaction same time to close the position of vault X but this time with a higher priority fee, being that the keeper operations are more time sensitive (robots/automated) there is a chance that it would want as much urgency than an average investor.
5. The validators on avax process the keepers transaction first and the position on vault x is closed.
6. When Bobs transaction is processed, it means that the vaults position has been closed, so bob will just be minted a share instead for his 100usd. Since the no position is open on the vault, it means bob will also loose his 5 avax permanently, as there is no mechanism to either refund bob or admin move it out.
7. The mechanism for moving fees is only on GMXproxy and not on the vault, and bobs fees will not make it to the proxy.



## Impact

User losses it fees for ever with no refund

## Tools Used

manaul 

## Recommendations

Refund fees when the vault position is closed.

## <a id='L-03'></a>L-03. Incorrect Token Price Validation in KeeperProxy

_Submitted by [dsbex](https://profiles.cyfrin.io/u/dsbex), [juggernaut63](https://profiles.cyfrin.io/u/juggernaut63), [biakia](https://profiles.cyfrin.io/u/biakia), [sohrabhind](https://profiles.cyfrin.io/u/sohrabhind), [petargvr94](https://profiles.cyfrin.io/u/petargvr94), [uzeyirch](https://profiles.cyfrin.io/u/uzeyirch), [kwakudr](https://profiles.cyfrin.io/u/kwakudr), [maze](https://profiles.cyfrin.io/u/maze), [acai](https://profiles.cyfrin.io/u/acai), [hawks](https://profiles.cyfrin.io/u/hawks), [sagsick](https://profiles.cyfrin.io/u/sagsick), [kirobrejka](https://profiles.cyfrin.io/u/kirobrejka), [bizarro](https://profiles.cyfrin.io/u/bizarro), [iampukar](https://profiles.cyfrin.io/u/iampukar), [josh4324](https://profiles.cyfrin.io/u/josh4324), [kvltbyte](https://profiles.cyfrin.io/u/kvltbyte), [farman1094](https://profiles.cyfrin.io/u/farman1094), [mrmorningstar](https://profiles.cyfrin.io/u/mrmorningstar), [hristoff_eth](https://profiles.cyfrin.io/u/hristoff_eth), [manga](https://profiles.cyfrin.io/u/manga), [ChainDefenders](https://codehawks.cyfrin.io/team/cm2bxupf00003grinaqv78qfm), [dharkartz](https://profiles.cyfrin.io/u/dharkartz), [udo](https://profiles.cyfrin.io/u/udo), [brene](https://profiles.cyfrin.io/u/brene), [bladesec](https://profiles.cyfrin.io/u/bladesec). Selected submission by: [juggernaut63](https://profiles.cyfrin.io/u/juggernaut63)._      
            


## Summary

The `KeeperProxy` contract contains a critical issue in its price validation logic, where the `longToken` price is validated against the `indexToken` price, not the corresponding `longToken` price. This mismatch in price validation can lead to invalid trades.

## Vulnerability Details

The issue exists in the `_validatePrice` function where price validation for `longToken` incorrectly uses `indexTokenPrice` instead of `longTokenPrice`:

```Solidity
function _validatePrice(address perpVault, MarketPrices memory prices) internal view {
    // ...
    MarketProps memory marketData = reader.getMarket(market);
    
    _check(marketData.indexToken, prices.indexTokenPrice.min);
    _check(marketData.indexToken, prices.indexTokenPrice.max);
    _check(marketData.longToken, prices.indexTokenPrice.min);  // Issue
    _check(marketData.longToken, prices.indexTokenPrice.max);  // Issue
    _check(marketData.shortToken, prices.shortTokenPrice.min);
    _check(marketData.shortToken, prices.shortTokenPrice.max);
}
```

The problem stems from using `indexTokenPrice` to validate `longToken`, This can lead to inaccurate price validation. Using `prices.indexTokenPrice` instead of `prices.longTokenPrice` to validate long token prices, thus breaking the integrity of the price validation mechanism.

## Impact

* Positions may be opened/closed at incorrect prices
* Unfair liquidations due to incorrect price validation

## Tools Used

* Manual review

## Recommendations

Correct price validation.

```Solidity
function _validatePrice(address perpVault, MarketPrices memory prices) internal view {
    // L2 Sequencer check...
    
    address market = IPerpetualVault(perpVault).market();
    IVaultReader reader = IPerpetualVault(perpVault).vaultReader();
    MarketProps memory marketData = reader.getMarket(market);
    
    // Correct price validation
    _check(marketData.indexToken, prices.indexTokenPrice.min);
    _check(marketData.indexToken, prices.indexTokenPrice.max);
    _check(marketData.longToken, prices.longTokenPrice.min);   // FIXED
    _check(marketData.longToken, prices.longTokenPrice.max);   // FIXED
    _check(marketData.shortToken, prices.shortTokenPrice.min);
    _check(marketData.shortToken, prices.shortTokenPrice.max);
    
    // Additional safety check
    require(
        prices.longTokenPrice.min <= prices.longTokenPrice.max,
        "Invalid long token price range"
    );
}
```

## <a id='L-04'></a>L-04. Protocol Recovery Mechanism at Risk Due to Unhandled Token Transfer Failures

_Submitted by [ccvascocc](https://profiles.cyfrin.io/u/ccvascocc), [kirobrejka](https://profiles.cyfrin.io/u/kirobrejka), [damilolaedwards](https://profiles.cyfrin.io/u/damilolaedwards), [t0x1c](https://profiles.cyfrin.io/u/t0x1c), [danielarmstrong](https://profiles.cyfrin.io/u/danielarmstrong), [ChainDefenders](https://codehawks.cyfrin.io/team/cm2bxupf00003grinaqv78qfm), [rampage](https://profiles.cyfrin.io/u/rampage), [vinica_boy](https://profiles.cyfrin.io/u/vinica_boy). Selected submission by: [rampage](https://profiles.cyfrin.io/u/rampage)._      
            



## Summary
The `PerpetualVault.sol` contract's flow cancellation mechanism can fail when token transfers are rejected, particularly during the `_cancelFlow()` operation. This creates a situation where the protocol's recovery mechanism becomes ineffective if the collateral token transfer is blocked (e.g., due to USDC blacklisting).

## Vulnerability Details
The vulnerability stems from the inconsistent handling of token transfers between two functions:

1. The `_transferToken()` function properly implements a try-catch mechanism:
```solidity

  /**
   * @dev Collect fee from the withdraw amount and transfer tokens to the user.
   *  Collect fee only when the user got the profit.
   */
  function _transferToken(uint256 depositId, uint256 amount) internal {
    uint256 fee;
    if (amount > depositInfo[depositId].amount) {
      fee = (amount - depositInfo[depositId].amount) * governanceFee / BASIS_POINTS_DIVISOR;
      if (fee > 0) {
        collateralToken.safeTransfer(treasury, fee);
      }
    }
    
->  try collateralToken.transfer(depositInfo[depositId].recipient, amount - fee) {}
    catch  {
      collateralToken.transfer(treasury, amount - fee);
      emit TokenTranferFailed(depositInfo[depositId].recipient, amount - fee);
    }
    totalDepositAmount -= depositInfo[depositId].amount;
    
    emit GovernanceFeeCollected(address(collateralToken), fee);
  }

```

2. However, the `_cancelFlow()` function lacks this safety mechanism:
```solidity
  function _cancelFlow() internal {
    if (flow == FLOW.DEPOSIT) {
      uint256 depositId = counter;
->    collateralToken.safeTransfer(depositInfo[depositId].owner, depositInfo[depositId].amount);
      totalDepositAmount = totalDepositAmount - depositInfo[depositId].amount;
      EnumerableSet.remove(userDeposits[depositInfo[depositId].owner], depositId);
      try IGmxProxy(gmxProxy).refundExecutionFee(
        depositInfo[counter].owner,
        depositInfo[counter].executionFee
      ) {} catch {}
      delete depositInfo[depositId];
    } else if (flow == FLOW.WITHDRAW) {
      try IGmxProxy(gmxProxy).refundExecutionFee(
        depositInfo[counter].owner,
        depositInfo[counter].executionFee
      ) {} catch {}
    }
    
    // Setting flow to liquidation has no meaning.
    // The aim is to run FINAIZE action. (swap indexToken to collateralToken);
    flow = FLOW.LIQUIDATION;
    nextAction.selector = NextActionSelector.FINALIZE;
  }
```

## Impact
- Protocol recovery operations may fail completely when token transfers are rejected
- User funds could become locked in the protocol
- While the owner can modify vault state through `setVaultState()`, this doesn't resolve the underlying issue of locked deposits

## Tools Used
Manual Code Review

## Recommendations
Implement consistent error handling in the `_cancelFlow()` function by adding a try-catch block for token transfers:

```solidity

  function _cancelFlow() internal {
    if (flow == FLOW.DEPOSIT) {
      uint256 depositId = counter;
-     collateralToken.safeTransfer(depositInfo[depositId].owner, depositInfo[depositId].amount);
+     try collateralToken.safeTransfer(depositInfo[depositId].owner, depositInfo[depositId].amount) {}
+     catch {
+       collateralToken.safeTransfer(treasury, depositInfo[depositId].amount);
+       emit TokenTransferFailed(depositInfo[depositId].owner, depositInfo[depositId].amount);
+     }
      totalDepositAmount = totalDepositAmount - depositInfo[depositId].amount;
      EnumerableSet.remove(userDeposits[depositInfo[depositId].owner], depositId);
      try IGmxProxy(gmxProxy).refundExecutionFee(
        depositInfo[counter].owner,
        depositInfo[counter].executionFee
      ) {} catch {}
      delete depositInfo[depositId];
    } else if (flow == FLOW.WITHDRAW) {
      try IGmxProxy(gmxProxy).refundExecutionFee(
        depositInfo[counter].owner,
        depositInfo[counter].executionFee
      ) {} catch {}
    }
    
    // Setting flow to liquidation has no meaning.
    // The aim is to run FINAIZE action. (swap indexToken to collateralToken);
    flow = FLOW.LIQUIDATION;
    nextAction.selector = NextActionSelector.FINALIZE;
  }
```
## <a id='L-05'></a>L-05. `_withdraw` function uses `shortTokenPrice.max` instead of `shortTokenPrice.min` when computing negative PnL adjustment, leading to underestimation of losses and excessive collateral withdrawal

_Submitted by [t0x1c](https://profiles.cyfrin.io/u/t0x1c), [0xl33](https://profiles.cyfrin.io/u/0xl33), [vinica_boy](https://profiles.cyfrin.io/u/vinica_boy), [infect3d](https://profiles.cyfrin.io/u/infect3d). Selected submission by: [infect3d](https://profiles.cyfrin.io/u/infect3d)._      
            


## Summary

Because Gamma create and manage GMX positions, it also uses GMX price functions to estimate assets values on GMX. GMX returns a min and max value when requesting a price.

When a user withdraws from the vault and the position has a negative PnL (loss), the function uses `prices.shortTokenPrice.max` to convert the loss amount from USD to token terms. This is incorrect as it should use `prices.shortTokenPrice.min` for conservatism in loss scenarios.

Using `shortTokenPrice.max` results in a smaller token amount subtracted from the withdrawal collateral (since dividing by a larger number yields a smaller result). This leads to users being able to withdraw more collateral than they should, effectively allowing them to avoid bearing their full share of losses.

## Vulnerability details

When a withdrawal is initiated from the vault via the `_withdraw` function, the amount of collateral that can be withdrawn by a user is calculated based on their proportional share of the vault. If the vault's position has a negative PnL (a loss), this loss should reduce the amount of collateral the user can withdraw.

The issue occurs on [L1112](https://github.com/CodeHawks-Contests/2025-02-gamma/blob/main/contracts/PerpetualVault.sol#L1112), where the negative PnL adjustment is calculated, and the problem is also present in the fee calculation on [L1109](https://github.com/CodeHawks-Contests/2025-02-gamma/blob/main/contracts/PerpetualVault.sol#L1109):

```solidity
File: contracts/PerpetualVault.sol
1089:   function _withdraw(uint256 depositId, bytes memory metadata, MarketPrices memory prices) internal {
1090:     uint256 shares = depositInfo[depositId].shares;
1091:     if (shares == 0) {
1092:       revert Error.ZeroValue();
1093:     } 
1094:     
1095:     if (positionIsClosed) {
1096:       _handleReturn(0, true, false);
1097:     } else if (_isLongOneLeverage(beenLong)) {
1098:       uint256 swapAmount = IERC20(indexToken).balanceOf(address(this)) * shares / totalShares;
1099:       nextAction.selector = NextActionSelector.SWAP_ACTION;     
1100:       // abi.encode(swapAmount, swapDirection): if swap direction is true, swap collateralToken to indexToken
1101:       nextAction.data = abi.encode(swapAmount, false);
1102:     } else if (curPositionKey == bytes32(0)) {    // vault liquidated
1103:       _handleReturn(0, true, false);
1104:     } else {
1105:       IVaultReader.PositionData memory positionData = vaultReader.getPositionInfo(curPositionKey, prices);
1106:       uint256 collateralDeltaAmount = positionData.collateralAmount * shares / totalShares;
1107:       uint256 sizeDeltaInUsd = positionData.sizeInUsd * shares / totalShares;
1108:       // we always charge the position fee of negative price impact case.
1109:       uint256 feeAmount = vaultReader.getPositionFeeUsd(market, sizeDeltaInUsd, false) / prices.shortTokenPrice.max;
1110:       int256 pnl = vaultReader.getPnl(curPositionKey, prices, sizeDeltaInUsd);
1111:       if (pnl < 0) {
1112:         collateralDeltaAmount = collateralDeltaAmount - feeAmount - uint256(-pnl) / prices.shortTokenPrice.max;
1113:       } else {
1114:         collateralDeltaAmount = collateralDeltaAmount - feeAmount;
1115:       }
1116:       uint256 acceptablePrice = abi.decode(metadata, (uint256));
1117:       _createDecreasePosition(collateralDeltaAmount, sizeDeltaInUsd, beenLong, acceptablePrice, prices);
1118:     }
1119:   }
```

In both cases, the contract uses `prices.shortTokenPrice.max` as the divisor when converting USD amounts to token amounts. This is fundamentally incorrect for a loss scenario:

1. When calculating losses, the contract should use the minimum token price for denominators (`prices.shortTokenPrice.min`) to ensure a more conservative estimation of the token equivalent of the loss.
2. Using the maximum price (`prices.shortTokenPrice.max`) results in a smaller token amount being deducted from the user's withdrawal.

## Impact

Users withdrawing when the position has a negative PnL will get more tokens that they should receive.

* Likelihood: high, as this happens on every withdrawal when the position has a negative PnL
* Impact: medium, as this impacts all users' funds and creates perverse economic incentives

## Recommended Mitigation Steps

Change the calculations to use `prices.shortTokenPrice.min` for both the fee and negative PnL adjustments:

```diff
  function _withdraw(uint256 depositId, bytes memory metadata, MarketPrices memory prices) internal {
    uint256 shares = depositInfo[depositId].shares;
    if (shares == 0) {
      revert Error.ZeroValue();
    } 
    
    if (positionIsClosed) {
      _handleReturn(0, true, false);
    } else if (_isLongOneLeverage(beenLong)) {
      uint256 swapAmount = IERC20(indexToken).balanceOf(address(this)) * shares / totalShares;
      nextAction.selector = NextActionSelector.SWAP_ACTION;     
      // abi.encode(swapAmount, swapDirection): if swap direction is true, swap collateralToken to indexToken
      nextAction.data = abi.encode(swapAmount, false);
    } else if (curPositionKey == bytes32(0)) {    // vault liquidated
      _handleReturn(0, true, false);
    } else {
      IVaultReader.PositionData memory positionData = vaultReader.getPositionInfo(curPositionKey, prices);
      uint256 collateralDeltaAmount = positionData.collateralAmount * shares / totalShares;
      uint256 sizeDeltaInUsd = positionData.sizeInUsd * shares / totalShares;
      // we always charge the position fee of negative price impact case.
-      uint256 feeAmount = vaultReader.getPositionFeeUsd(market, sizeDeltaInUsd, false) / prices.shortTokenPrice.max;
+      uint256 feeAmount = vaultReader.getPositionFeeUsd(market, sizeDeltaInUsd, false) / prices.shortTokenPrice.min;
      int256 pnl = vaultReader.getPnl(curPositionKey, prices, sizeDeltaInUsd);
      if (pnl < 0) {
-        collateralDeltaAmount = collateralDeltaAmount - feeAmount - uint256(-pnl) / prices.shortTokenPrice.max;
+        collateralDeltaAmount = collateralDeltaAmount - feeAmount - uint256(-pnl) / prices.shortTokenPrice.min;
      } else {
        collateralDeltaAmount = collateralDeltaAmount - feeAmount;
      }
      uint256 acceptablePrice = abi.decode(metadata, (uint256));
      _createDecreasePosition(collateralDeltaAmount, sizeDeltaInUsd, beenLong, acceptablePrice, prices);
    }
  }
```

This change ensures that the contract uses the most conservative price when accounting for losses, which correctly protects the vault and remaining users from excessive withdrawals.

## <a id='L-06'></a>L-06. PerpetualVault withdrawals are affected by global parameter updates

_Submitted by [codertjay](https://profiles.cyfrin.io/u/codertjay), [uncontrolledking](https://profiles.cyfrin.io/u/uncontrolledking), [riceee](https://profiles.cyfrin.io/u/riceee), [cipherhawk](https://profiles.cyfrin.io/u/cipherhawk). Selected submission by: [riceee](https://profiles.cyfrin.io/u/riceee)._      
            


### Summary

If the protocol changes the `lockTime`, it should only apply to new deposits and not affect existing ones. If the lock period is extended, users might be forced to keep their funds locked for a longer time than originally expected, preventing planned timely withdrawals during losses or profits. Conversely, if the lock period is shortened, early withdrawals from older deposits could disrupt trading strategies, leading to forced liquidations or premature position closures.

### Impact

* **Extended Lock Period:** Users unable to withdraw during desired periods, potentially leading to forced losses or reduced profits.
* **Reduced Lock Period:** Unplanned withdrawals might disrupt vault strategies, causing position liquidations or premature position closures.

### Recommendations

* Implement logic to ensure `lockTime` changes only apply to future deposits.\
  add a `uint256 lockTime` variable to the `DepositInfo` struct
  and check for lock durations using each deposits respective lockTime and not the global parameter.

```solidity
function withdraw(address recipient, uint256 depositId) public payable nonReentrant {
        _noneFlow();
        flow = FLOW.WITHDRAW;
        flowData = depositId;

        if (recipient == address(0)) {
            revert Error.ZeroValue();
        }
        //Use local lockTime parameter
        if (depositInfo[depositId].timestamp + depositInfo[depositId].lockTime >= block.timestamp) {
            revert Error.Locked();
        }
        [...]
}
```

## <a id='L-07'></a>L-07. If Vault Was Liquidated And There Was A Withdrawal Flow Then Fee Should Be Refunded

_Submitted by [sakshamseth5](https://profiles.cyfrin.io/u/sakshamseth5)._      
            


## Summary

The issue in short is that when a user has requested a withdraw and the vault gets liquidated with sizeInTokens as 0 , then there would not be a decrease order made on GMX (because of liquidation) and the user would be paid from whatever was received after liquidation and the user's shares , in this case the user should be refunded for the fees since there was no GMX order made , but we will see how there was no refund made to the user.

## Vulnerability Details

Consider the following ->

1.) There is an active perp vault position on GMX with leverage > 1x.

2.) A user has requested a withdraw using `withdraw()` and pays the execution fee ->

\[<https://github.com/CodeHawks-Contests/2025-02-gamma/blob/main/contracts/PerpetualVault.sol#L272>]

the flow is assigned as WITHDRAW at L255 , and since `if (curPositionKey != bytes32(0))` (cause a position is open on GMX with leverage > 1x) ->

```solidity
if (curPositionKey != bytes32(0)) {
      nextAction.selector = NextActionSelector.WITHDRAW_ACTION;
      _settle();  // Settles any outstanding fees and updates state before processing withdrawal
    }
```

Therefore , next action is WITHDRAW\_ACTION and `_settle()` is called.

3.) Inside `_settle()` a settle order is created (routed through GmxProxy.sol) ->

```solidity
function _settle() internal {
    IGmxProxy.OrderData memory orderData = IGmxProxy.OrderData({
      market: market,
      indexToken: indexToken,
      initialCollateralToken: address(collateralToken),
      swapPath: new address[](0),
      isLong: beenLong,
      sizeDeltaUsd: 0,
      initialCollateralDeltaAmount: 0,
      amountIn: 0,
      callbackGasLimit: callbackGasLimit,
      acceptablePrice: 0,
      minOutputAmount: 0
    });
    _gmxLock = true;
    gmxProxy.settle(orderData);
  }
```

4.) After a successful settle order , `afterOrderExecution()` would be invoked by GmxProxy and nextAction would be assigned as `WITHDRAW_ACTION` ->

```solidity
if (orderResultData.isSettle) {
      nextAction.selector = NextActionSelector.WITHDRAW_ACTION;
      emit GmxPositionCallbackCalled(requestKey, true);
      return;
    }
```

5.) Now lets say the position in GMX got fully liquidated , therefore `afterLiquidationExecution()` would be invoked (L563) ->

```solidity
function afterLiquidationExecution() external { 
    if (msg.sender != address(gmxProxy)) {
      revert Error.InvalidCall();
    }

    depositPaused = true;
    uint256 sizeInTokens = vaultReader.getPositionSizeInTokens(curPositionKey);
    if (sizeInTokens == 0) {
      delete curPositionKey;
    }

    if (flow == FLOW.NONE) {
      flow = FLOW.LIQUIDATION;
      nextAction.selector = NextActionSelector.FINALIZE;
    } else if (flow == FLOW.DEPOSIT) {
      flowData = sizeInTokens;
    } else if (flow == FLOW.WITHDRAW) {
      // restart the withdraw flow even though current step is FINALIZE.
      nextAction.selector = NextActionSelector.WITHDRAW_ACTION;
    }
```

and since `sizeInTokens` would be 0 (fully liquidated ) then `curPositionKey` would be deleted (would be 0 now) and since flow was WITHDRAW , nextAction.selector would be assigned WITHDRAW\_ACTION

6.) Then keeper would invoke `runNextAction()` and since nextAction is `WITHDRAW_ACTION` , this branch would be invoked (L371-L381)->

```solidity
else if (_nextAction.selector == NextActionSelector.WITHDRAW_ACTION) {
      // swap indexToken that could be generated from settle action or liquidation/ADL into collateralToken
      // use only DexSwap
      if (
        IERC20(indexToken).balanceOf(address(this)) * prices.indexTokenPrice.min >= ONE_USD
      ) {
        (, bytes memory data) = abi.decode(metadata[1], (PROTOCOL, bytes));
        _doDexSwap(data, false);
      }
      uint256 depositId = flowData;
      _withdraw(depositId, metadata[0], prices);
```

Therefore `_withdraw()` is invoked.

7.) And inside withdraw , this branch would be invoked since curPositionKey = 0 (L1102) , ->

```solidity
} else if (curPositionKey == bytes32(0)) {    // vault liquidated
      _handleReturn(0, true, false);
    }
```

8.) In the above `_handleReturn`  call `refundFee` parameter has been set to false (3rd parameter) , but this is incorrect , since in this case no decrease orders were opened in GMX (which happen in the last else case in `_withdraw`) and therefore the user should have been refunded the fee.

9.) Therefore after the collateral is transferred in \_handleReturn() there was no refund which is wrong as explained above.

## Impact

In case the position got liquidated , there was no decrease order made on GMX , hence the user should not have been charged the fee and should have been given a refund , but in the above flow we see user will not receive a refund when vault is liquidated.

## Tools Used

Manual analysis

## Recommendations

Instead do

```solidity
} else if (curPositionKey == bytes32(0)) {    // vault liquidated
      _handleReturn(0, true, true);
    } 
```

## <a id='L-08'></a>L-08. Calculating price impact collateral is incorrect when calculating users' increase from deposit

_Submitted by [vinica_boy](https://profiles.cyfrin.io/u/vinica_boy)._      
            


## Summary

When calculating the price impact from an increase position, we first calculate what is the expected amount without price impact and what is the actual amount. Based on the difference we get the price impact. The problem in Gamma implementation is that for both short and long positions, we use min price of index token to get the size delta in token when we should be using max price for long positions and min price for short positions.

## Vulnerability Details

Taking a look into `PositionUtils::getExecutionPriceForIncrease()` in GMX [code](https://github.com/gmx-io/gmx-synthetics/blob/b8fb11349eb59ae48a1834c239669d4ad63a38b5/contracts/position/PositionUtils.sol#L621-L714), we first calculate `baseSizeDeltaInTokens` which is the amount without price impact (this is semantically the same as expected delta in size tokens in Gamma).

```solidity
		uint256 baseSizeDeltaInTokens;

        if (params.position.isLong()) {
            // round the number of tokens for long positions down
            baseSizeDeltaInTokens = params.order.sizeDeltaUsd() / indexTokenPrice.max;
        } else {
            // round the number of tokens for short positions up
            baseSizeDeltaInTokens = Calc.roundUpDivision(params.order.sizeDeltaUsd(), indexTokenPrice.min);
        }
```

We see that there is different calculation of the amount of tokens based on if the position is short or long, while in Gamma (`VaultReader::getPriceImpactInCollateral()`) we always use min price:

```Solidity
  function getPriceImpactInCollateral(
    bytes32 positionKey,
    uint256 sizeDeltaInUsd,
    uint256 prevSizeInTokens,
    MarketPrices memory prices
  ) external view returns (int256) {
    // @audit min/max depending on short/long
    uint256 expectedSizeInTokensDelta = sizeDeltaInUsd / prices.indexTokenPrice.min;
    uint256 curSizeInTokens = getPositionSizeInTokens(positionKey);
    uint256 realSizeInTokensDelta = curSizeInTokens - prevSizeInTokens;
    int256 priceImpactInTokens = expectedSizeInTokensDelta.toInt256() - realSizeInTokensDelta.toInt256();
    int256 priceImpactInCollateralTokens = priceImpactInTokens * prices.indexTokenPrice.min.toInt256() / prices.shortTokenPrice.min.toInt256();
    return priceImpactInCollateralTokens;
  }
```

## Impact

Incorrect price impact calculations leading to unfair shares allocation since users' deposits are adjusted based on the calculated price impact when minting shares.

## Tools Used

Manual review.

## Recommendations

Consider checking if position is long or short and use the correct price to match the actual calculation in GMX.

## <a id='L-09'></a>L-09. Settlement Flow Can Be Disrupted When Market Decrease Order is Disabled

_Submitted by [0xl33](https://profiles.cyfrin.io/u/0xl33), [danielarmstrong](https://profiles.cyfrin.io/u/danielarmstrong), [rampage](https://profiles.cyfrin.io/u/rampage), [bladesec](https://profiles.cyfrin.io/u/bladesec). Selected submission by: [rampage](https://profiles.cyfrin.io/u/rampage)._      
            



## Summary
The `settle()` function in `GmxProxy.sol` lacks a validation check for the market decrease order execution feature being enabled, which could lead to a cyclic cancellation flow when a user attempts to withdraw.

## Vulnerability Details

In the `GmxProxy.sol` contract, there is a discrepancy in validation checks between the `createOrder()` and `settle()` functions.

The `createOrder()` function properly validates if the execution feature is enabled for the specific order type:

```solidity

  /**
  * @notice Creates an order.
  * @dev This function requires the receipient to be the perpetual vault and ensures sufficient ETH balance for the execution fee.
  *      It handles token approvals, transfers, and constructs the order parameters before creating the order via `gExchangeRouter`.
  * @param orderType The type of the order (e.g., MarketIncrease, MarketDecrease, etc.).
  * @param orderData The data associated with the order.
  * @return The request key of the created order.
  */
  function createOrder(
    Order.OrderType orderType,
    IGmxProxy.OrderData memory orderData
  ) public returns (bytes32) {
    require(msg.sender == perpVault, "invalid caller");
    uint256 positionExecutionFee = getExecutionGasLimit(
      orderType,
      orderData.callbackGasLimit
    ) * tx.gasprice;
    require(
      address(this).balance >= positionExecutionFee,
      "insufficient eth balance"
    );
    
    // check if execution feature is enabled
    bytes32 executeOrderFeatureKey = keccak256(
      abi.encode(
        EXECUTE_ORDER_FEATURE_DISABLED,
        orderHandler,
        orderType
      )
    );
    require(
      dataStore.getBool(executeOrderFeatureKey) == false,
      "gmx execution disabled"
    );

    gExchangeRouter.sendWnt{value: positionExecutionFee}(
      orderVault,
      positionExecutionFee
    );
    if (
      orderType == Order.OrderType.MarketSwap ||
      orderType == Order.OrderType.MarketIncrease
    ) {
      IERC20(orderData.initialCollateralToken).safeApprove(
        address(gmxRouter),
        orderData.amountIn
      );
      gExchangeRouter.sendTokens(
        orderData.initialCollateralToken,
        orderVault,
        orderData.amountIn
      );
    }
    CreateOrderParamsAddresses memory paramsAddresses = CreateOrderParamsAddresses({
      receiver: perpVault,
      cancellationReceiver: address(perpVault),
      callbackContract: address(this),
      uiFeeReceiver: address(0),
      market: orderData.market,
      initialCollateralToken: orderData.initialCollateralToken,
      swapPath: orderData.swapPath
    });

    CreateOrderParamsNumbers memory paramsNumber = CreateOrderParamsNumbers({
      sizeDeltaUsd: orderData.sizeDeltaUsd,
      initialCollateralDeltaAmount: orderData.initialCollateralDeltaAmount,
      triggerPrice: 0,
      acceptablePrice: orderData.acceptablePrice,
      executionFee: positionExecutionFee,
      callbackGasLimit: orderData.callbackGasLimit,
      minOutputAmount: orderData.minOutputAmount,      // this param is used when swapping. is not used in opening position even though swap involved.
      validFromTime: 0
    });
    CreateOrderParams memory params = CreateOrderParams({
      addresses: paramsAddresses,
      numbers: paramsNumber,
      orderType: orderType,
      decreasePositionSwapType: Order
        .DecreasePositionSwapType
        .SwapPnlTokenToCollateralToken,
      isLong: orderData.isLong,
      shouldUnwrapNativeToken: false,
      autoCancel: false,
      referralCode: referralCode
    });
    bytes32 requestKey = gExchangeRouter.createOrder(params);
    queue.requestKey = requestKey;
    return requestKey;
  }
```

However, the `settle()` function lacks this crucial check:

```solidity

  /**
  * @notice Settles an order by creating a MarketDecrease order with minimal collateral delta amount.
  * @dev This function calculates the execution fee, ensures sufficient ETH balance, sets up the order parameters,
  *      and creates the order via the `gExchangeRouter`.
  * @param orderData The data associated with the order, encapsulated in an `OrderData` struct.
  * @return The request key of the created order.
  */
  function settle(
    IGmxProxy.OrderData memory orderData
  ) external returns (bytes32) {
    require(msg.sender == perpVault, "invalid caller");
    uint256 positionExecutionFee = getExecutionGasLimit(
      Order.OrderType.MarketDecrease,
      orderData.callbackGasLimit
    ) * tx.gasprice;
    require(
      address(this).balance >= positionExecutionFee,
      "insufficient eth balance"
    );
    gExchangeRouter.sendWnt{value: positionExecutionFee}(
      orderVault,
      positionExecutionFee
    );
    CreateOrderParamsAddresses memory paramsAddresses = CreateOrderParamsAddresses({
      receiver: perpVault,
      cancellationReceiver: address(perpVault),
      callbackContract: address(this),
      uiFeeReceiver: address(0),
      market: orderData.market,
      initialCollateralToken: orderData.initialCollateralToken,
      swapPath: new address[](0)
    });
    CreateOrderParamsNumbers memory paramsNumber = CreateOrderParamsNumbers({
      sizeDeltaUsd: 0,
      initialCollateralDeltaAmount: 1,
      triggerPrice: 0,
      acceptablePrice: 0,
      executionFee: positionExecutionFee,
      callbackGasLimit: orderData.callbackGasLimit,
      minOutputAmount: 0,      // this param is used when swapping. is not used in opening position even though swap involved.
      validFromTime: 0
    });
    CreateOrderParams memory params = CreateOrderParams({
      addresses: paramsAddresses,
      numbers: paramsNumber,
      orderType: Order.OrderType.MarketDecrease,
      decreasePositionSwapType: Order
        .DecreasePositionSwapType
        .SwapPnlTokenToCollateralToken,
      isLong: orderData.isLong,
      shouldUnwrapNativeToken: false,
      autoCancel: false,
      referralCode: referralCode
    });
    bytes32 requestKey = gExchangeRouter.createOrder(params);
    queue.requestKey = requestKey;
    queue.isSettle = true;
    return requestKey;
  }
```

When the MarketDecrease order type is disabled, this leads to a problematic cycle where:
1. The settle order gets canceled
2. `PerpetualVault.sol#afterOrderCancellation()` triggers another settlement attempt
3. The cycle repeats
```solidity

  /**
  * @notice Callback function triggered when an order execution on GMX is canceled due to an error.
  * @param requestKey The request key of the executed order.
  * @param orderType The type of order.
  * @param orderResultData The result data of the order execution.
  */
  function afterOrderCancellation(
    bytes32 requestKey,
    Order.OrderType orderType,
    IGmxProxy.OrderResultData memory orderResultData
  ) external {
    if (msg.sender != address(gmxProxy)) {
      revert Error.InvalidCall();
    }
    _gmxLock = false;

    if (orderResultData.isSettle) {
      // Retry settle action.
      nextAction.selector = NextActionSelector.SETTLE_ACTION;
    } else if (orderType == Order.OrderType.MarketSwap) {
      // If GMX swap fails, retry in the next action.
      nextAction.selector = NextActionSelector.SWAP_ACTION;
      // abi.encode(swapAmount, swapDirection): if swap direction is true, swap collateralToken to indexToken
      nextAction.data = abi.encode(swapProgressData.remaining, swapProgressData.isCollateralToIndex);
    } else {
      if (flow == FLOW.DEPOSIT) {
        nextAction.selector = NextActionSelector.INCREASE_ACTION;
        nextAction.data = abi.encode(beenLong);
      } else if (flow == FLOW.WITHDRAW) {
        nextAction.selector = NextActionSelector.WITHDRAW_ACTION;
      } else {
        // If signal change fails, the offchain script starts again from the current status.
        delete flowData;
        delete flow;
      }
    }
    emit GmxPositionCallbackCalled(requestKey, false);
  }
```
## Impact
- Creates an infinite loop of failed settlement attempts
- Forces keepers to manually cancel flows to recover
- Allows malicious users to cause temporary protocol disruption through strategic withdrawals
- Wastes keeper resources and gas

## Tools Used
Manual Review

## Recommendations
Add the execution feature validation check to the `settle()` function:

```solidity
  function settle(
    IGmxProxy.OrderData memory orderData
  ) external returns (bytes32) {
    require(msg.sender == perpVault, "invalid caller");

+   // check if execution feature is enabled.
+   byte32 executeOrderFeatureKey = keccak256(
+     abi.encode(
+       EXECUTE_ORDER_FEATURE_DISABLED,
+       orderHandler,
+       Order.OrderType.MarketDecrease
+     )
+   );
+   require(
+     dataStore.getBool(executeOrderFeatureKey) == false,
+     "gmx execution disabled"
+   );

    ........................................................
  }
```

## <a id='L-10'></a>L-10. `positionIsClosed` not being set to `true` leads to new position being opened on GMX without a signal from offchain, and users not receiving execution fee refund

_Submitted by [0xl33](https://profiles.cyfrin.io/u/0xl33)._      
            


**Description:**

The root cause of this issue can have two similar impacts, which I will explain with 2 different scenarios:

*Scenario* *`1`:*

A position is open on GMX and a user decices to withdraw, but due to market conditions, the position collateral will not be enough to withdraw the user's position, so the order's `sizeDeltaInUsd` gets set to the whole position size:

```solidity
        if (
            sizeDeltaInUsd == 0 // if size delta is 0
                || vaultReader.willPositionCollateralBeInsufficient( // or if insufficient collateral
                prices, curPositionKey, market, _isLong, sizeDeltaInUsd, collateralDeltaAmount)
        ) {
@>          sizeDeltaInUsd = sizeInUsd; // sets size delta to full position size
        }
```

In the code snippet above we can see that if `willPositionCollateralBeInsufficient` function returns `true`, `sizeDeltaInUsd` gets set to the whole position size.

When GMX executes the `MarketDecrease` order request, `PerpetualVault::afterOrderExecution` will get called and this part of the function will trigger (the fees have been settled in previous order):

```solidity
} else if (orderResultData.orderType == Order.OrderType.MarketDecrease) {
    uint256 sizeInUsd = vaultReader.getPositionSizeInUsd(curPositionKey);
@>  if (sizeInUsd == 0) {
        delete curPositionKey;
    }
    if (flow == FLOW.WITHDRAW) {
        nextAction.selector = NextActionSelector.FINALIZE;
        uint256 prevCollateralBalance = collateralToken.balanceOf(address(this)) - orderResultData.outputAmount;
        nextAction.data = abi.encode(prevCollateralBalance, sizeInUsd == 0, false);
```

In the snippet above we can see that only `curPositionKey` gets deleted, but `positionIsClosed` is not set to `true`, even though the position is closed on GMX.

Due to this, when a new user calls `PerpetualVault::deposit`, a `MarketIncrease` order request will be sent to GMX to increase the position, but the position is closed at this time, so GMX will open a new position, and the user, along with the next depositors, will pay the execution fee, when in reality, the position should be closed at this time and when there is no open position, depositors should not pay an execution fee.

*Scenario* *`2`, which results in users not receiving execution fee refund when they should:*

Users who call `withdraw` function always pay execution fee when `positionIsClosed` is `false`, but they do not get refunded in the scenario where `positionIsClosed` is `false` and `curPositionKey` is `0` at the same time, which can happen when GMX executes a `MarketDecrease` order request and `PerpetualVault::afterOrderExecution` gets called, if the order completely closes the GMX position. This scenario happens when the flow is `WITHDRAW`. Here is the relevant code snippet:

```solidity
} else if (orderResultData.orderType == Order.OrderType.MarketDecrease) {
    uint256 sizeInUsd = vaultReader.getPositionSizeInUsd(curPositionKey);
@>  if (sizeInUsd == 0) {
        delete curPositionKey;
    }
```

In the code snippet above, only `curPositionKey` is deleted, but `positionIsClosed` is not set to `true`, so if, after this withdrawal gets finalized, another user calls `withdraw`, he will pay an execution fee, but will not get refunded, when in reality, the GMX position is closed and the keeper did not open a new one yet.

Reminding you that this is how it's posssible for a single user to close the entire GMX position:

```solidity
        if (
            sizeDeltaInUsd == 0 // if size delta is 0
                || vaultReader.willPositionCollateralBeInsufficient( // or if insufficient collateral
                prices, curPositionKey, market, _isLong, sizeDeltaInUsd, collateralDeltaAmount)
        ) {
@>          sizeDeltaInUsd = sizeInUsd; // sets size delta to full position size
        }
```

As you can see, if `VaultReader::willPositionCollateralBeInsufficient` returns `true`, the whole GMX position will be closed in the following order execution. This function can return `true` for multiple reasons:

* major negative PnL
* heavily changed market prices at withdrawal time (decreased collateral value)
* open interest constraints (increased collateral requirements)

In this scenario, there could be other users that possess shares, and if they call `withdraw` after the current `MarketDecrease` order executes, they will pay the execution fee and will not get refunded, even though the GMX position is closed and all remaining funds are in the vault.

Here is a code snippet from `withdraw` function, which shows that users will pay an execution fee (`positionIsClosed` is still `false` at this point) and then `_withdraw` gets called:

```solidity
@> _payExecutionFee(depositId, false);
        if (curPositionKey != bytes32(0)) {
        nextAction.selector = NextActionSelector.WITHDRAW_ACTION;
        _settle();  // Settles any outstanding fees and updates state before processing withdrawal
@>      } else {
        MarketPrices memory prices;
@>      _withdraw(depositId, hex'', prices);
        }
}
```

In the below code snippet we see that `_handleReturn` function gets called with the last parameter set to `false`. This is a problem, because in this case the position on GMX is closed, which means the funds are in the vault, so the execution fee should be refunded.

```solidity
function _withdraw(uint256 depositId, bytes memory metadata, MarketPrices memory prices) internal {
    uint256 shares = depositInfo[depositId].shares;
    if (shares == 0) {
        revert Error.ZeroValue();
    }
    
    if (positionIsClosed) {
        _handleReturn(0, true, false);
    } else if (_isLongOneLeverage(beenLong)) {  // beenLong && leverage == BASIS_POINTS_DIVISOR
        uint256 swapAmount = IERC20(indexToken).balanceOf(address(this)) * shares / totalShares;
        nextAction.selector = NextActionSelector.SWAP_ACTION;
        // abi.encode(swapAmount, swapDirection): if swap direction is true, swap collateralToken to indexToken
        nextAction.data = abi.encode(swapAmount, false);
    } else if (curPositionKey == bytes32(0)) {
@>      _handleReturn(0, true, false);
    }
```

```solidity
function _handleReturn(uint256 withdrawn, bool positionClosed, bool refundFee) internal {
```

In the code snippet above, we can see that the third parameter is `refundFee`, which gets checked at the end of `_handleReturn` function:

```solidity
@>  if (refundFee) {
      uint256 usedFee = callbackGasLimit * tx.gasprice;
      if (depositInfo[depositId].executionFee > usedFee) {
        try IGmxProxy(gmxProxy).refundExecutionFee(depositInfo[counter].owner, depositInfo[counter].executionFee - usedFee) {} catch {}
      }
    }
```

**Impact:**

Scenario `1`:

All depositors, after the issue occurs, have to pay an execution fee, when in reality they should not pay because position should be closed until keeper opens it. Additionally, first depositor after the issue occurs basically creates a new position on GMX when the keeper did not plan it and, by design, all positions should only be opened by a keeper, based on signals.

Scenario `2`:

Users who still have shares after a GMX position gets closed will call `withdraw` and will not receive execution fee refund.

**Likelihood:**

The issue can happen when a user wants to withdraw, but position collateral is not enough, and this can occur due to various market conditions, such as:

* major negative PnL
* heavily changed market prices at withdrawal time (decreased collateral value)
* open interest constraints (increased collateral requirements)

**Proof of Concept:**

Scenario `1`:

1. Add the test provided below to `PerpetualVault.t.sol`
2. Run the test with this command: `forge test --mt test_PositionIsClosed_NotSetToTrue --via-ir --rpc-url <YOUR_RPC_URL_HERE> -vv`
3. In terminal you should see output like this:

Logs:\
total amount after alice's withdrawal: 0\
curPositionKey: 0\
positionIsClosed: false

1. Read the comments in the provided test to understand what's happening

```solidity
    function test_PositionIsClosed_NotSetToTrue() external {
        address keeper = PerpetualVault(vault2x).keeper();

        // Alice deposits

        address alice = makeAddr("alice");
        depositFixtureInto2x(alice, 10e9);
        MarketPrices memory prices = mockData.getMarketPrices();
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encode(3390000000000000);
        vm.prank(keeper);
        PerpetualVault(vault2x).run(true, true, prices, data);
        PerpetualVault.FLOW flow = PerpetualVault(vault2x).flow();
        assertEq(uint8(flow), 2);
        assertEq(PerpetualVault(vault2x).positionIsClosed(), true);
        (PerpetualVault.NextActionSelector selector,) = PerpetualVault(vault2x).nextAction();
        assertEq(uint8(selector), 0);
        GmxOrderExecuted2x(true);
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, new bytes[](0));

        // Setting up for withdrawal

        uint256[] memory aliceDepositIds = PerpetualVault(vault2x).getUserDeposits(alice);
        uint256 executionFee = PerpetualVault(vault2x).getExecutionGasLimit(false);
        uint256 lockTime = 1;
        PerpetualVault(vault2x).setLockTime(lockTime);
        vm.warp(block.timestamp + lockTime + 1);
        bytes[] memory swapData = new bytes[](2);
        swapData[0] = abi.encode(0);

        // Alice withdraws

        deal(alice, 1 ether);
        vm.prank(alice);
        PerpetualVault(vault2x).withdraw{value: executionFee * tx.gasprice}(alice, aliceDepositIds[0]);
        GmxOrderExecuted2x(true); // settle order execution
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, swapData); // creates market decrease order
        GmxOrderExecuted2x(true); // withdraw (market decrease) execution
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, new bytes[](0)); // finalizing

        // Making sure position is closed

        console.log("total amount after alice's withdrawal:", PerpetualVault(vault2x).totalAmount(prices));
        console.log("curPositionKey:", uint256(PerpetualVault(vault2x).curPositionKey()));
        console.log("positionIsClosed:", PerpetualVault(vault2x).positionIsClosed());
        assertEq(PerpetualVault(vault2x).totalAmount(prices), 0); // totalAmount is 0
        assertEq(uint256(PerpetualVault(vault2x).curPositionKey()), 0); // curPositionKey is deleted
        assertEq(PerpetualVault(vault2x).positionIsClosed(), false); // positionIsClosed not updated !!!

        // Bob deposits

        address bob = makeAddr("bob");
        deal(bob, 1 ether);
        uint256 bobsEthBalanceBeforeDeposit = address(bob).balance;
        depositFixtureInto2x(bob, 10e9);
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, data);
        GmxOrderExecuted2x(true); // order execution
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, new bytes[](0)); // finalizing
        uint256 bobsEthBalanceAfterDeposit = address(bob).balance;
        assertTrue(bobsEthBalanceAfterDeposit < bobsEthBalanceBeforeDeposit); // Bob pays execution fee, even though he deposited when there was no open position on GMX !!!
    }
```

Scenario `2`:

1. Add the test provided below to `PerpetualVault.t.sol`
2. Run the test with this command: `forge test --mt test_ExecutionFee_NotRefunded --via-ir --rpc-url <YOUR_RPC_URL_HERE> -vv`
3. In terminal you should see output like this:

Logs:\
curPositionKey: 0\
positionIsClosed: false

1. Read the comments in the provided test to understand what's happening

```solidity
    function test_ExecutionFee_NotRefunded() external {
        address keeper = PerpetualVault(vault2x).keeper();

        // Alice deposits

        address alice = makeAddr("alice");
        depositFixtureInto2x(alice, 10e9);
        MarketPrices memory prices = mockData.getMarketPrices();
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encode(3390000000000000);
        vm.prank(keeper);
        PerpetualVault(vault2x).run(true, true, prices, data);
        assertEq(PerpetualVault(vault2x).positionIsClosed(), true);
        GmxOrderExecuted2x(true);
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, new bytes[](0));

        // Bob deposits

        address bob = makeAddr("bob");
        deal(bob, 1 ether);
        depositFixtureInto2x(bob, 10e9);
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, data);
        GmxOrderExecuted2x(true); // order execution
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, new bytes[](0)); // finalizing

        // Setting up for withdrawal

        uint256[] memory aliceDepositIds = PerpetualVault(vault2x).getUserDeposits(alice);
        uint256 executionFee = PerpetualVault(vault2x).getExecutionGasLimit(false);
        uint256 lockTime = 1;
        PerpetualVault(vault2x).setLockTime(lockTime);
        vm.warp(block.timestamp + lockTime + 1);
        bytes[] memory swapData = new bytes[](2);
        swapData[0] = abi.encode(0);
        bytes4 selector = bytes4(
            keccak256(
                "willPositionCollateralBeInsufficient(((uint256,uint256),(uint256,uint256),(uint256,uint256)),bytes32,address,bool,uint256,uint256)"
            )
        );
        vm.mockCall(address(reader), selector, abi.encode(true)); // mocking scenario where `willPositionCollateralBeInsufficient` returns `true`

        // Alice withdraws and GMX position gets closed

        deal(alice, 1 ether);
        vm.prank(alice);
        PerpetualVault(vault2x).withdraw{value: executionFee * tx.gasprice}(alice, aliceDepositIds[0]);
        GmxOrderExecuted2x(true); // settle order execution
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, swapData); // creates market decrease order
        GmxOrderExecuted2x(true); // withdraw (market decrease) execution
        vm.prank(keeper);
        PerpetualVault(vault2x).runNextAction(prices, new bytes[](0)); // finalizing

        // Making sure GMX position is closed

        console.log("curPositionKey:", uint256(PerpetualVault(vault2x).curPositionKey()));
        console.log("positionIsClosed:", PerpetualVault(vault2x).positionIsClosed());
        assertEq(uint256(PerpetualVault(vault2x).curPositionKey()), 0); // curPositionKey is deleted
        assertEq(PerpetualVault(vault2x).positionIsClosed(), false); // positionIsClosed not updated !!!

        uint256[] memory bobDepositIds = PerpetualVault(vault2x).getUserDeposits(bob);
        (, uint256 bobShares,,,,) = PerpetualVault(vault2x).depositInfo(bobDepositIds[0]);
        assertGt(bobShares, 0); // Bob has shares

        IERC20 collateralToken = PerpetualVault(vault2x).collateralToken();
        assertGt(collateralToken.balanceOf(vault2x), 0); // vault has USDC

        // Bob withdraws

        uint256 bobsEthBalanceBeforeWithdraw = address(bob).balance;
        vm.prank(bob);
        PerpetualVault(vault2x).withdraw{value: executionFee * tx.gasprice}(bob, bobDepositIds[0]);
        uint256 bobsEthBalanceAfterWithdraw = address(bob).balance;
        assertTrue(bobsEthBalanceAfterWithdraw < bobsEthBalanceBeforeWithdraw); // Bob pays and does not get refunded the execution fee, even though he withdrew when there was no open position on GMX !!!
        assertEq(PerpetualVault(vault2x).positionIsClosed(), false); // positionIsClosed still `false`
    }
```

**Recommended Mitigation:**

Set `positionIsClosed` to `true` if after a `MarketDecrease` order execution, current position size is 0.

```diff
} else if (orderResultData.orderType == Order.OrderType.MarketDecrease) {
    uint256 sizeInUsd = vaultReader.getPositionSizeInUsd(curPositionKey);
    if (sizeInUsd == 0) {
        delete curPositionKey;
+       positionIsClosed = true;
    }
    if (flow == FLOW.WITHDRAW) {
        nextAction.selector = NextActionSelector.FINALIZE;
        uint256 prevCollateralBalance = collateralToken.balanceOf(address(this)) - orderResultData.outputAmount;
        nextAction.data = abi.encode(prevCollateralBalance, sizeInUsd == 0, false);
```

Additionally, consider setting the last parameter to `true` when calling `_handleReturn` in this situation:

```diff
function _withdraw(uint256 depositId, bytes memory metadata, MarketPrices memory prices) internal {
    uint256 shares = depositInfo[depositId].shares;
    if (shares == 0) {
        revert Error.ZeroValue();
    }
    
    if (positionIsClosed) {
        _handleReturn(0, true, false);
    } else if (_isLongOneLeverage(beenLong)) {  // beenLong && leverage == BASIS_POINTS_DIVISOR
        uint256 swapAmount = IERC20(indexToken).balanceOf(address(this)) * shares / totalShares;
        nextAction.selector = NextActionSelector.SWAP_ACTION;
        // abi.encode(swapAmount, swapDirection): if swap direction is true, swap collateralToken to indexToken
        nextAction.data = abi.encode(swapAmount, false);
    } else if (curPositionKey == bytes32(0)) {
-       _handleReturn(0, true, false);
+       _handleReturn(0, true, true);
    }
```

## <a id='L-11'></a>L-11. Locked funds due to overflow via shares decimal scaling

_Submitted by [codexbugmenot](https://profiles.cyfrin.io/u/codexbugmenot), [wellbyt3](https://profiles.cyfrin.io/u/wellbyt3). Selected submission by: [wellbyt3](https://profiles.cyfrin.io/u/wellbyt3)._      
            


## Summary
Liquidations inflate the share decimals to dilute existing holders. Over successive liquidations, this exponential share inflation can trigger arithmetic overflows during withdrawal calculations, locking funds and potentially causing significant losses for users.

## Vulnerability Details

When shares are first minted to depositors, they use 14 decimals (6 decimals for USDC \* 1e8):

However, the number of decimals can increase when a liquidation occurs.

Let's say there are 100,000e14 shares and there's an open 2x leverage long position. A user deposits 1000e6 USDC to the position, but before runNextAction() is called by a keeper, a liquidation occurs liquidating the entire position.

Gamma doesn't burn the 100,000e14 shares, but instead dilutes them to them point where they are essentially worthless. This is done in the shares calculation.

First, we calculate the `totalAmountBefore`, which is the total value of the vault prior to the deposit. Since the position is liquidated this will be 0.

Then we multiple the amount deposited by the total number of shares and then divide by `totalAmountBefore` to determine how many shares to mint.

To avoid a divide by 0 error, Gamma updates 0 to 1:

```Solidity
function _mint(uint256 depositId, uint256 amount, bool refundFee, MarketPrices memory prices) internal {
    uint256 _shares;
    if (totalShares == 0) {
      _shares = depositInfo[depositId].amount * 1e8;
    } else {
      uint256 totalAmountBefore;
      if (positionIsClosed == false && _isLongOneLeverage(beenLong)) {
        totalAmountBefore = IERC20(indexToken).balanceOf(address(this)) - amount;
      } else {
@>      totalAmountBefore = _totalAmount(prices) - amount;
      }
@>    if (totalAmountBefore == 0) totalAmountBefore = 1;
@>    _shares = amount * totalShares / totalAmountBefore;
    }

    depositInfo[depositId].shares = _shares;
    totalShares = totalShares + _shares;

...SNIP...
  }

```

Now, when we mint the depositor their shares, they receive 1000e6 \* 100,000e14 / 1 shares = 1000e25.

Since the prior 100,000e14 shareholders position was liquidated, their shares are only now worth \~.0000001% of the position.

This seems to work, but a big problem arrises the more the vault gets liquidated.

Let's say the next time a liquidation occurs, the vault has 100,000e25 shares. The next depositor would receive 1000e6 \* 100,000e25 = 1000e36 shares

Since shares are a uint256, the maximum value is 2^256 - 1 or approximately \~1.157e77.

It's reasonable to assume that each time a liquidation occurs, the decimals on shares get scaled up somewhere between 9 and 11 decimal places, which means that after \~6 liquidations, we'd be approaching the max value of a uint256.

This poses huge problems when a user attempts to withdraw their funds. When `\_withdraw` is called there are multiple places (denoted below) where an overflow could occur because shares are multiplied by something:

```Solidity
function _withdraw(uint256 depositId, bytes memory metadata, MarketPrices memory prices) internal {
    uint256 shares = depositInfo[depositId].shares;
    if (shares == 0) {
      revert Error.ZeroValue();
    }
    
    if (positionIsClosed) {
      _handleReturn(0, true, false);
    } else if (_isLongOneLeverage(beenLong)) {  // beenLong && leverage == BASIS_POINTS_DIVISOR
      uint256 swapAmount = IERC20(indexToken).balanceOf(address(this)) * shares / totalShares;
      nextAction.selector = NextActionSelector.SWAP_ACTION;
      nextAction.data = abi.encode(swapAmount, false);
    } else if (curPositionKey == bytes32(0)) {    
      _handleReturn(0, true, false);
    } else {
      IVaultReader.PositionData memory positionData = vaultReader.getPositionInfo(curPositionKey, prices);
@>    uint256 collateralDeltaAmount = positionData.collateralAmount * shares / totalShares;
@>    uint256 sizeDeltaInUsd = positionData.sizeInUsd * shares / totalShares;
  ...SNIP...

    }
  }

```
The overflow would lead to funds becoming stuck for withdrawers. 

It's important to point out that this overflow can occur if there's less than 6 liquidations depending on how large the value shares is being multiplied against. For example, sizeDeltaInUSD uses 30 decimals, so if shares approach 77-30 = 47 decimals, this overflow is a risk and would only take ~3 liquidations.

## Impact
Loss of funds.

## Tools Used
Manual review.

## Recommendations
Consider potentially burning the shares of users when a position is liquidated so decimals don't scale.

## <a id='L-12'></a>L-12.  Execution Fee Refund Issue in `cancelFlow` Leading to Potential Revert

_Submitted by [cybrid](https://profiles.cyfrin.io/u/cybrid), [pkqs90](https://profiles.cyfrin.io/u/pkqs90). Selected submission by: [cybrid](https://profiles.cyfrin.io/u/cybrid)._      
            


## Summary

The `cancelFlow` function fully refunds the execution fee to the withdrawer, but since the `gmxProxy` has already paid the settlement transaction fee, this can lead to an issue where `gmxProxy` ends up covering the cost. If `gmxProxy` does not have enough ETH, the `cancelFlow` transaction reverts, preventing withdrawal cancellation.

## Vulnerability Details

* The `withdraw` function requires double the execution fee since it includes both the settlement and actual withdrawal transactions.
* The settlement order is executed immediately, deducting the first execution fee.
* If `cancelFlow` is called before the actual withdrawal transaction, it refunds the full execution fee to the withdrawer.
* Since `gmxProxy` has already paid for the settlement transaction, it bears the cost.
* If `gmxProxy` has insufficient ETH to cover the settlement fee, `cancelFlow` reverts, leading to a failed cancellation.

## Impact

* Users may be unable to cancel withdrawals if `gmxProxy` lacks funds.
* Potential Loss of Funds from the `gmxProxy`.

## POC

paste in /test/PerpetualVault.t.sol

```solidity
function test_WithdrawExecutionFeeReturn() external {
        address gmxProxy = address(PerpetualVault(vault).gmxProxy());
        address keeper = PerpetualVault(vault).keeper();
        address alice = makeAddr("alice");
        depositFixture(alice, 1e10);

        MarketPrices memory prices = mockData.getMarketPrices();
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encode(3380000000000000);
        vm.prank(keeper);
        PerpetualVault(vault).run(true, false, prices, data);
        PerpetualVault.FLOW flow = PerpetualVault(vault).flow();
        assertEq(uint8(flow), 2);
        GmxOrderExecuted(true);

        vm.prank(keeper);
        PerpetualVault(vault).runNextAction(prices, new bytes[](0));

        uint256[] memory depositIds = PerpetualVault(vault).getUserDeposits(
            alice
        );
        uint256 executionFee = PerpetualVault(vault).getExecutionGasLimit(
            false
        );

        uint256 lockTime = 1;
        PerpetualVault(vault).setLockTime(lockTime);
        vm.warp(block.timestamp + lockTime + 1);

        payable(alice).transfer(1 ether);
        vm.prank(alice);

        uint bal = address(gmxProxy).balance;
        PerpetualVault(vault).withdraw{value: executionFee * tx.gasprice}(
            alice,
            depositIds[0]
        );
        GmxOrderExecuted(true);

        vm.prank(keeper);
        PerpetualVault(vault).cancelFlow();

        console.log((bal - address(gmxProxy).balance) > 0);
    }

```

## Recommendations

Partial Refund Instead of Full Refund: Modify cancelFlow to refund only the withdrawal execution fee while keeping the settlement execution fee covered.

## <a id='L-13'></a>L-13. indexToken should be swapped to collateralToken before Compound action

_Submitted by [pkqs90](https://profiles.cyfrin.io/u/pkqs90)._      
            


## Summary

indexToken should be swapped to collateralToken before Compound action

## Vulnerability Details

The Compound action is used to move idle funds in vault to deposit into GMX. These funds can either be from funding fees or adl/liquidation.

For positive funding fees, it will be collected in indexToken, and needs to be swapped to collateralToken before compounding.

<https://github.com/CodeHawks-Contests/2025-02-gamma/blob/main/contracts/PerpetualVault.sol#L399>

```solidity
    } else if (positionIsClosed == false && _isFundIdle()) {
@>    flow = FLOW.COMPOUND;
      if (_isLongOneLeverage(beenLong)) {
        _runSwap(metadata, true, prices);
      } else {
        (uint256 acceptablePrice) = abi.decode(metadata[0], (uint256));
        _createIncreasePosition(beenLong, acceptablePrice, prices);
      }
    } 
```

## Impact

Some funding fees will be left idle in PerpetualVault as indexToken.

## Tools Used

N/A

## Recommendations

Also perform the indexToken->collateralToken dex swap before the compound action.





​    