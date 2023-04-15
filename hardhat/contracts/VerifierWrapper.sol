// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Verifier.sol";

contract VerifierWrapper is Verifier {
    uint maxMsgSize;

    constructor(uint _maxMsgSize) {
        maxMsgSize = _maxMsgSize;
    }

    function verify(
        bytes32 commitmentHash,
        bytes32 featureHash,
        bytes32 messageHash,
        bytes memory message,
        bytes memory proof
    ) public view returns (bool) {
        uint256[] memory pubInputs = new uint256[](3 + maxMsgSize);
        pubInputs[0] = uint256(commitmentHash);
        pubInputs[1] = uint256(featureHash);
        pubInputs[2] = uint256(messageHash);
        for (uint i = 0; i < message.length / 16; i++) {
            uint coeff = 1;
            for (uint j = 0; j < 16; j++) {
                pubInputs[3 + i] += coeff * uint256(uint8(message[16 * i + j]));
                coeff = coeff << 8;
            }
        }
        for (uint i = message.length / 16; i < maxMsgSize / 16; i++) {
            pubInputs[3 + i] = 0;
        }
        return Verifier.verify(pubInputs, proof);
    }
}
