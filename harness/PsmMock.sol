// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.21;

contract PsmMock {
    address public lastUsr;
    uint256 public lastGemAmount;
    address public lastSender;
    bytes4  public lastSig;
    uint256 public retValue;

    function sellGemNoFee(address usr, uint256 gemAmt) external {
        lastUsr = usr;
        lastGemAmount = gemAmt;
        lastSender = msg.sender;
        lastSig = msg.sig;
    }

    function buyGemNoFee(address usr, uint256 gemAmt) external {
        lastUsr = usr;
        lastGemAmount = gemAmt;
        lastSender = msg.sender;
        lastSig = msg.sig;
    }

    function fill() external returns (uint256) {
        return retValue;
    }
}
