// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./VerifierInternal.sol";

// Original: https://zenn.dev/qope/scraps/e14176fc816dde
contract Verifier is VerifierInternal {
    address yulVerifier;
    uint wordSize;
    uint maxMsgSize;

    constructor(address _yulVerifier, uint _wordSize, uint _maxMsgSize) {
        yulVerifier = _yulVerifier;
        wordSize = _wordSize;
        maxMsgSize = _maxMsgSize;
    }

    function verify(
        bytes memory commitment,
        bytes32 featureHash,
        bytes memory message,
        bytes32 messageHash,
        bytes calldata proof
    ) public view returns (bool) {
        bytes memory commitmentBytes = new bytes(32 * wordSize);
        for (uint idx = 0; idx < commitment.length; idx++) {
            commitmentBytes[32 * idx + 31] = commitmentBytes[idx];
        }
        bytes memory featureHashBytes = new bytes(32 * 32);
        for (uint idx = 0; idx < 32; idx++) {
            featureHashBytes[32 * idx + 31] = featureHash[idx];
        }
        bytes memory messageBytes = new bytes(32 * maxMsgSize);
        for (uint idx = 0; idx < messageBytes.length; idx++) {
            messageBytes[32 * idx + 31] = message[idx];
        }
        bytes memory messageHashBytes = new bytes(32 * 32);
        for (uint idx = 0; idx < 32; idx++) {
            messageHashBytes[32 * idx + 31] = messageHash[idx];
        }
        bytes memory input = abi.encodePacked(
            commitmentBytes,
            featureHashBytes,
            messageBytes,
            messageHashBytes,
            proof
        );
        return _verify(input);
    }

    function _verify(bytes memory input) private view returns (bool) {
        (bool success, ) = yulVerifier.staticcall(input);
        return success;
    }
}
