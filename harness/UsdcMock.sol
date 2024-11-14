// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.21;

contract UsdcMock {
    address public lastTo;
    uint256 public lastAmount;
    address public lastSender;
    bytes4  public lastSig;

    function approve(address to, uint256 amount) external returns (bool) {
        lastTo = to;
        lastAmount = amount;
        lastSender = msg.sender;
        lastSig = msg.sig;
        return true;
    }
}
