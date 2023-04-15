// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Verifier.sol";
import "./ENS.sol";

contract VoiceKeyRecover is Verifier {
    using ENSNamehash for bytes;
    struct VoiceData {
        address owner;
        bytes32 featureHash;
        bytes commitment;
    }

    mapping(address => bool) public isRegistered;
    mapping(address => VoiceData) public voiceDataOfWallet;
    mapping(bytes32 => bool) public usedMessageHashes;

    ENS ens = ENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    constructor(
        address _yulVerifier,
        uint _wordSize,
        uint _maxMsgSize
    ) Verifier(_yulVerifier, _wordSize, _maxMsgSize) {}

    function getOwner() public view returns (address) {
        require(isRegistered[msg.sender], "not registered");
        return voiceDataOfWallet[msg.sender].owner;
    }

    function register(
        address walletAddr,
        bytes32 featureHash,
        bytes calldata commitment
    ) public {
        require(!isRegistered[walletAddr], "already registered");
        voiceDataOfWallet[walletAddr] = VoiceData(
            msg.sender,
            featureHash,
            commitment
        );
    }

    function recover(
        address walletAddr,
        string calldata oldENS,
        string calldata newENS,
        bytes32 messageHash,
        bytes calldata proof
    ) public {
        require(isRegistered[walletAddr], "The wallet is not registered");
        require(!usedMessageHashes[messageHash], "Message hash already used");
        VoiceData memory voiceData = voiceDataOfWallet[walletAddr];
        address oldOwner = voiceData.owner;
        require(oldOwner == resolveENS(oldENS), "Invalid old ENS");
        string memory message = string.concat(
            "Recover the ENS ",
            oldENS,
            " to a new ENS ",
            newENS
        );
        require(
            verify(
                voiceData.commitment,
                voiceData.featureHash,
                bytes(message),
                messageHash,
                proof
            ),
            "invalid proof"
        );
        usedMessageHashes[messageHash] = true;
        address newOwner = resolveENS(newENS);
        voiceDataOfWallet[walletAddr].owner = newOwner;
    }

    function resolveENS(string calldata ensName) public view returns (address) {
        bytes32 node = bytes(ensName).namehash();
        Resolver resolver = ens.resolver(node);
        return resolver.addr(node);
    }
}
