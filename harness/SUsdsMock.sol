// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.21;

contract SUsdsMock {
    address public lastTo;
    uint256 public lastAmount;
    uint256 public lastAssets;
    uint256 public lastShares;
    address public lastReceiver;
    address public lastOwner;
    address public lastSender;
    bytes4  public lastSig;
    uint256 public retValue;

    function approve(address to, uint256 amount) external returns (bool) {
        lastTo = to;
        lastAmount = amount;
        lastSender = msg.sender;
        lastSig = msg.sig;
        return true;
    }

    function deposit(uint256 assets, address receiver) external returns (uint256) {
        lastAssets = assets;
        lastReceiver = receiver;
        lastSender = msg.sender;
        lastSig = msg.sig;
        return retValue;
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256) {
        lastAssets = assets;
        lastReceiver = receiver;
        lastOwner = owner;
        lastSender = msg.sender;
        lastSig = msg.sig;
        return retValue;
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256) {
        lastShares = shares;
        lastReceiver = receiver;
        lastOwner = owner;
        lastSender = msg.sender;
        lastSig = msg.sig;
        return retValue;
    }
}
