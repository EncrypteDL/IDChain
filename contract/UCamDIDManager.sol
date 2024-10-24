// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import './Agentable.sol';
import './DIDManagerBase.sol';

contract UCamDIDManager is Agentable, DIDManagerBase {
    bytes private alphabet = "0123456789abcdef";

    constructor(address _dbAddr) DIDBase(_dbAddr, "did:io:ucam") public {}

    function formDID(bytes20 uid) internal view returns (bytes memory) {

        bytes memory str = new bytes(40);
        for (uint i = 0; i < 20; i++) {
            str[i*2] = alphabet[uint8(uid[i] >> 4)];
            str[1+i*2] = alphabet[uint8(uid[i] & 0x0f)];
        }
        return abi.encodePacked(db.getPrefix(), string(str));
    }

    function decodeInternalKey(bytes memory did) public view returns (bytes20) {
        require(hasPrefix(did, db.getPrefix()), "invalid DID");
        bytes memory domainID = (slice(did, db.getPrefix().length));
        require(domainID.length == 40, "invalid DID");
        uint160 uid = 0;
        uint160 b1;
        uint160 b2;
        for (uint i = 0; i < 40; i += 2){
            uid *= 256;
            b1 = uint8(domainID[i]);
            b2 = uint8(domainID[i+1]);
            if ((b1 >= 97)&&(b1 <= 102)) b1 -= 87;
            else if ((b1 >= 48)&&(b1 <= 57)) b1 -= 48;
            if ((b2 >= 97)&&(b2 <= 102)) b2 -= 87;
            else if ((b2 >= 48)&&(b2 <= 57)) b2 -= 48;
            uid += (b1*16+b2);
        }
        return bytes20(uid);
    }

    function createDIDByAgent(bytes20 uid, bytes32 h, bytes memory uri, address authorizer, bytes memory auth) public onlyOwner {
        bytes memory did = formDID(uid);
        require(authorizer == getSigner(getCreateAuthMessage(did, h, uri, msg.sender), auth), "invalid signature");
        internalCreateDID(did, uid, authorizer, h, uri);
    }

    function updateDIDByAgent(bytes20 uid, bytes32 h, bytes memory uri, bytes memory auth) public {
        bytes memory did = formDID(uid);
        (address authorizer, ,) = db.get(uid);
        require(authorizer == getSigner(getUpdateAuthMessage(did, h, uri, msg.sender), auth), "invalid signature");
        internalUpdateDID(did, uid, authorizer, h, uri);
    }

    function deleteDIDByAgent(bytes20 uid, bytes memory auth) public {
        bytes memory did = formDID(uid);
        (address authorizer, ,) = db.get(uid);
        require(authorizer == getSigner(getDeleteAuthMessage(did, msg.sender), auth), "invalid signature");
        internalDeleteDID(did, uid, authorizer);
    }
}