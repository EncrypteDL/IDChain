// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;


/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */


contract Ownable{
    address public owner;
    event OwnershipTransfer(address indexed previosOwner, address indexed newOwner);

    constructor() public{
        owner = msg.sender;
    }

    modifier onlyOwner(){
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner{
        require(newOwner != address(0));
        emit OwnershipTransfer(owner, newOwner);
        owner = newOwner;
    }

}