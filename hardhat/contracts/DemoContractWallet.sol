// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4;

import "./VoiceKeyRecover.sol";
import "hardhat/console.sol";

contract DemoContractWallet {
    VoiceKeyRecover vkr;

    constructor(address _vkr) {
        vkr = VoiceKeyRecover(_vkr);
        vkr.registerOwner(msg.sender);
    }

    function getEthBalance() public view returns (uint) {
        require(msg.sender == vkr.getOwner(), "only owner");
        return address(this).balance;
    }

    function depositEth() public payable {
        require(msg.sender == vkr.getOwner(), "only owner");
    }

    function transferEth(address payable to, uint amount) public {
        require(msg.sender == vkr.getOwner(), "only owner");
        require(address(this).balance >= amount, "too large amount");
        to.transfer(amount);
    }
}
