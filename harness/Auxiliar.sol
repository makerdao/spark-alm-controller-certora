// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.21;

contract Auxiliar {

    function makeAssetKey(bytes32 key, address asset) external pure returns (bytes32) {
        return keccak256(abi.encode(key, asset));
    }

    function makeDomainKey(bytes32 key, uint32 domain) external pure returns (bytes32) {
        return keccak256(abi.encode(key, domain));
    }
}
