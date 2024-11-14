// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.21;

contract DaiMock {
    address public lastTo;
    uint256 public lastAmount;
    address public lastSender;
    bytes4  public lastSig;
    uint256 public retValue;

    function balanceOf(address) external view returns (uint256) {
        return retValue;
    }

    function approve(address to, uint256 amount) external {
        lastTo = to;
        lastAmount = amount;
        lastSender = msg.sender;
        lastSig = msg.sig;
    }
}
