// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IZKPSnarkVerifier {
    function verifyProof(bytes memory _proof, bytes32[] memory _publicInputs) external returns (bool);
}
