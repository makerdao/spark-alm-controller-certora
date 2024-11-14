// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.21;

contract CctpMock {
    address public localMinter;
    uint256 public lastAmount;
    uint32  public lastDestinationDomain;
    bytes32 public lastMintRecipient;
    address public lastToken;
    address public lastSender;
    bytes4  public lastSig;
    uint256 public times;
    uint64  public retValue;

    function depositForBurn(uint256 amount, uint32 destinationDomain, bytes32 mintRecipient, address token) external returns (uint64) {
        lastAmount = amount;
        lastDestinationDomain = destinationDomain;
        lastMintRecipient = mintRecipient;
        lastToken = token;
        lastSender = msg.sender;
        lastSig = msg.sig;
        times++;
        return retValue;
    }
}
