// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IZKPSnarkVerifier.sol";

contract VoiceAuth {
    struct VoiceData {
        string currentENS;
        bytes32 ZKPCommitment;
        bytes voiceFeatures;
    }

    IZKPSnarkVerifier public zkpVerifier;
    mapping(address => VoiceData) public voiceDataMapping;
    mapping(bytes32 => bool) public usedMessageHashes;

    constructor(address _zkpVerifier) {
        zkpVerifier = IZKPSnarkVerifier(_zkpVerifier);
    }

    function register(
        address wallet,
        string memory currentENS,
        bytes32 ZKPCommitment,
        bytes memory voiceFeatures
    ) public {
        voiceDataMapping[wallet] = VoiceData(currentENS, ZKPCommitment, voiceFeatures);
    }

    function recover(
        address wallet,
        string memory newENS,
        bytes memory zkProof,
        bytes32 messageHash
    ) public {
        require(!usedMessageHashes[messageHash], "Message hash already used");

        VoiceData storage voiceData = voiceDataMapping[wallet];
        bytes32[] memory publicInputs = new bytes32[](3);
        publicInputs[0] = voiceData.ZKPCommitment;
        publicInputs[1] = keccak256(abi.encodePacked(newENS));
        publicInputs[2] = messageHash;

        require(zkpVerifier.verifyProof(zkProof, publicInputs), "ZKP verification failed");

        usedMessageHashes[messageHash] = true;
        voiceData.currentENS = newENS;
    }
}
