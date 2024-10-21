// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./ownership/whitlist.sol";

contract TrackerService is whitelist{
    uint256 unitPrice;
    uint256 maximumAccessPeriod;

    event UpdateUnitPrice(uint256 unitPrice);
    event UpdateMaximumAccessPeriod(uint256 maximumAccessPeriod);
    event RequestDataPointAccess(string indexed publicKey, uint256 expirationTime);
    event ShareAccessToken(string associationToken, string indexed tokenUserPublicKey);

    constructor(uint256 _unitPrice, uint256 _maximumAccessPeriod) public {
        addAddressToWhitelist(msg.sender);
        unitPrice = _unitPrice;
        maximumAccessPeriod = _maximumAccessPeriod;
    }

    function updateUnitPrice(uint256 _unitPrice) public onlyWhitelist() {
        unitPrice = _unitPrice;
        emit UpdateUnitPrice(_unitPrice);
    }

    function updateMaximumAccessPeriod(uint256 _maximumAccessPeriod) public onlyWhitelist() {
        maximumAccessPeriod = _maximumAccessPeriod;
        emit UpdateMaximumAccessPeriod(_maximumAccessPeriod);
    }

    function requestDataPointAccess(string publicKey, uint256 expirationTime) public payable {
        if (unitPrice != 0) {
            require(msg.value % unitPrice == 0, "invalid payment amount");
        }
        require(expirationTime > now && expirationTime - now <= maximumAccessPeriod, "invalid expiration time");

        emit RequestDataPointAccess(publicKey, expirationTime);
    }

    function shareAccessToken(string associationToken, string tokenUserPublicKey) public onlyWhitelist {
        emit ShareAccessToken(associationToken, tokenUserPublicKey);
    }
}