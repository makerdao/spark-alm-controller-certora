// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.21;

contract DaiUsdsMock {
    address public lastUsr;
    uint256 public lastWad;
    address public lastSender;
    bytes4  public lastSig;

    function daiToUsds(address usr, uint256 wad) external {
        lastUsr = usr;
        lastWad = wad;
        lastSender = msg.sender;
        lastSig = msg.sig;
    }

    function usdsToDai(address usr, uint256 wad) external {
        lastUsr = usr;
        lastWad = wad;
        lastSender = msg.sender;
        lastSig = msg.sig;
    }
}
