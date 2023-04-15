// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4;

import "./VerifierWrapper.sol";

// import "./ENS.sol";

contract VoiceKeyRecover is VerifierWrapper {
    // using ENSNamehash for bytes;
    struct VoiceData {
        address owner;
        bytes32 featureHash;
        bytes32 commitmentHash;
        bytes commitment;
    }

    mapping(address => bool) public isRegistered;
    mapping(address => VoiceData) public voiceDataOfWallet;
    mapping(bytes32 => bool) public usedMessageHashes;

    // ENS ens;

    constructor(uint _maxMsgSize) VerifierWrapper(_maxMsgSize) {
        // ens = ENS(_ens);
    }

    function getOwner() public view returns (address) {
        require(isRegistered[msg.sender], "not registered");
        return voiceDataOfWallet[msg.sender].owner;
    }

    function register(
        address walletAddr,
        bytes32 featureHash,
        bytes32 commitmentHash,
        bytes calldata commitment
    ) public {
        require(!isRegistered[walletAddr], "already registered");
        voiceDataOfWallet[walletAddr] = VoiceData(
            msg.sender,
            featureHash,
            commitmentHash,
            commitment
        );
        isRegistered[walletAddr] = true;
    }

    function recover(
        address walletAddr,
        bytes32 messageHash,
        bytes calldata proof
    ) public {
        require(isRegistered[walletAddr], "The wallet is not registered");
        require(!usedMessageHashes[messageHash], "Message hash already used");
        VoiceData memory voiceData = voiceDataOfWallet[walletAddr];
        address oldOwner = voiceData.owner;
        address newOwner = msg.sender;
        // require(oldOwner == resolveENS(oldENS), "Invalid old ENS");
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
        // address newOwner = resolveENS(newENS);
        // address newOwner = msg.sender;
        voiceDataOfWallet[walletAddr].owner = newOwner;
    }

    // function resolveENS(string calldata ensName) public view returns (address) {
    //     bytes32 node = bytes(ensName).namehash();
    //     Resolver resolver = ens.resolver(node);
    //     return resolver.addr(node);
    // }
}
