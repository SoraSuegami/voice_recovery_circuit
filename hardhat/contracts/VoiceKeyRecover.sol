// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4;

import "./VerifierWrapper.sol";

contract VoiceKeyRecover is VerifierWrapper {
    struct VoiceData {
        bytes32 featureHash;
        bytes32 commitmentHash;
        bytes commitment;
    }

    mapping(address => bool) public isRegistered;
    mapping(address => address) public ownerOfWallet;
    mapping(address => VoiceData) public voiceDataOfWallet;
    mapping(bytes32 => bool) public usedMessageHashes;

    constructor(uint _maxMsgSize) VerifierWrapper(_maxMsgSize) {}

    function getOwner() public view returns (address) {
        require(isRegistered[msg.sender], "not registered");
        return ownerOfWallet[msg.sender];
    }

    function registerOwner(address owner) public {
        require(!isRegistered[msg.sender], "already registered");
        isRegistered[msg.sender] = true;
        ownerOfWallet[msg.sender] = owner;
    }

    function registerVoiceOfWallet(
        address walletAddr,
        bytes32 featureHash,
        bytes32 commitmentHash,
        bytes calldata commitment
    ) public {
        require(isRegistered[walletAddr], "not registered");
        require(msg.sender == ownerOfWallet[walletAddr], "not owner");
        voiceDataOfWallet[walletAddr] = VoiceData(
            featureHash,
            commitmentHash,
            commitment
        );
    }

    function recover(
        address walletAddr,
        bytes32 messageHash,
        bytes calldata proof
    ) public {
        require(isRegistered[walletAddr], "The wallet is not registered");
        require(!usedMessageHashes[messageHash], "Message hash already used");
        VoiceData memory voiceData = voiceDataOfWallet[walletAddr];
        address oldOwner = ownerOfWallet[walletAddr];
        address newOwner = msg.sender;
        bytes memory message = abi.encodePacked(oldOwner, newOwner);
        require(
            VerifierWrapper.verify(
                voiceData.commitmentHash,
                voiceData.featureHash,
                messageHash,
                message,
                proof
            ),
            "invalid proof"
        );
        usedMessageHashes[messageHash] = true;
        ownerOfWallet[walletAddr] = newOwner;
    }

    function getMessageOfRecover(
        address walletAddr
    ) public view returns (bytes memory) {
        require(isRegistered[walletAddr], "The wallet is not registered");
        address oldOwner = ownerOfWallet[walletAddr];
        address newOwner = msg.sender;
        bytes memory message = abi.encodePacked(oldOwner, newOwner);
        return message;
    }
}
