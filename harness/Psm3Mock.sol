// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.21;

contract Psm3Mock {
    address public lastAsset;
    address public lastReceiver;
    uint256 public lastAmount;
    address public lastSender;
    bytes4  public lastSig;
    uint256 public retValue;

    function deposit(address asset, address receiver, uint256 amount) external returns (uint256) {
        lastAsset = asset;
        lastReceiver = receiver;
        lastAmount = amount;
        lastSender = msg.sender;
        lastSig = msg.sig;
        return retValue;
    }

    function withdraw(address asset, address receiver, uint256 amount) external returns (uint256) {
        lastAsset = asset;
        lastReceiver = receiver;
        lastAmount = amount;
        lastSender = msg.sender;
        lastSig = msg.sig;
        return retValue;
    }
}
