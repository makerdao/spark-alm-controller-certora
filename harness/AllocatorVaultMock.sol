// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.21;

contract AllocatorVaultMock {
    uint256 public lastAmount;
    address public lastSender;
    bytes4  public lastSig;

    function draw(uint256 amount) external {
        lastAmount = amount;
        lastSender = msg.sender;
        lastSig = msg.sig;
    }

    function wipe(uint256 amount) external {
        lastAmount = amount;
        lastSender = msg.sender;
        lastSig = msg.sig;
    }
}
