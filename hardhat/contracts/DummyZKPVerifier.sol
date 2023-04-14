// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IZKPSnarkVerifier.sol";

contract DummyZKPVerifier is IZKPSnarkVerifier {
    bool public verificationResult;

    function setVerificationResult(bool _verificationResult) public {
        verificationResult = _verificationResult;
    }

    function verifyProof(bytes memory _proof, bytes32[] memory _publicInputs) external override returns (bool) {
        return verificationResult;
    }
}
