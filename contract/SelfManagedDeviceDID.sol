// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface SelfManagedDeviceDID {
    function createDID(string memory uuid, bytes memory proof, bytes32 hash, string memory uri) external;
    function deleteDID(string memory uuid, bytes memory proof) external;
    function updateHash(string memory uuid, bytes memory proof, bytes32 hash) external;
    function updateURI(string memory uuid, bytes memory proof, string memory uri) external;
    function getHash(string memory did) external view returns (bytes32);
    function getURI(string memory did) external view returns (string memory);
}
