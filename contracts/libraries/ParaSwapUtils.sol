// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IAugustusSwapper {
  function getTokenTransferProxy() external view returns (address);
}
// abi.encodeWithSelector(bytes4(keccak256("swap(address,bytes)")), 0x80,0,0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57,123,999,0);
library ParaSwapUtils {
  using SafeERC20 for IERC20;

  /*
   * @audit Q:这个函数会被PerpetualVault::_doDexSwap()调用，_doDexSwap()最终被runNextAction() onlykeeper调用
   *         如果这个swap有问题，且keeper也不老实，则会出现事故
   *         1. swap有没有问题
   *         2. keeper有没有问题
   */
  function swap(address to, bytes memory callData) external {
    _validateCallData(to, callData);
    address approvalAddress = IAugustusSwapper(to).getTokenTransferProxy();
    address fromToken;
    uint256 fromAmount;
    assembly {
      fromToken := mload(add(callData, 68)) // 4+2x32
      fromAmount := mload(add(callData, 100)) // 4+3x32
    }//shoud check the function signature and limit the amount
    IERC20(fromToken).safeApprove(approvalAddress, fromAmount);//calldata指向地方可以被人为修改，
    (bool success, ) = to.call(callData);//keeper可以随意call任何函数,甚至可以不去做任何事情。
    require(success, "paraswap call reverted");
  }
  //@audit Q6: f hell, hardcode this address???
  function _validateCallData(address to, bytes memory callData) internal view {
    require(to == address(0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57), "invalid paraswap callee");
    address receiver;
    assembly {
      //@audit M:Hight-- this hardcode offset is fucking hell,classic abi smuggling bug
      //        bro, i can send a callData with receiver==address(this)
      receiver := mload(add(callData, 196))//读取calldata指针指向的位置的值，再向后移动196个字节，即4+6x32
    }
    require(receiver == address(this), "invalid paraswap calldata");
  }
}