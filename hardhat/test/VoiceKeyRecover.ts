import { ethers } from "hardhat";
import { Signer, Contract } from "ethers";
import { expect } from "chai";

describe("VoiceAuth", function () {
  let accounts: Signer[];
  let VoiceAuth: Contract;
  let DummyZKPVerifier: Contract;

  beforeEach(async function () {
    accounts = await ethers.getSigners();

    const DummyZKPVerifierFactory = await ethers.getContractFactory("DummyZKPVerifier");
    DummyZKPVerifier = await DummyZKPVerifierFactory.deploy();
    await DummyZKPVerifier.deployed();

    const VoiceAuthFactory = await ethers.getContractFactory("VoiceAuth");
    VoiceAuth = await VoiceAuthFactory.deploy(DummyZKPVerifier.address);
    await VoiceAuth.deployed();
  });

  it("should register voice data", async function () {
    const wallet = await accounts[0].getAddress();
    const currentENS = "example1.eth";
    const ZKPCommitment = ethers.utils.keccak256("0x1234");
    const voiceFeatures = ethers.utils.randomBytes(32);

    await VoiceAuth.register(wallet, currentENS, ZKPCommitment, voiceFeatures);

    const registeredData = await VoiceAuth.voiceDataMapping(wallet);
    expect(registeredData.currentENS).to.equal(currentENS);
    expect(registeredData.ZKPCommitment).to.equal(ZKPCommitment);
    expect(ethers.utils.hexlify(registeredData.voiceFeatures)).to.equal(ethers.utils.hexlify(voiceFeatures));
  });

  it("should recover and update ENS", async function () {
    const wallet = await accounts[0].getAddress();
    const currentENS = "example1.eth";
    const newENS = "example2.eth";
    const ZKPCommitment = ethers.utils.keccak256("0x1234");
    const voiceFeatures = ethers.utils.randomBytes(32);
    const zkProof = ethers.utils.randomBytes(192); // Dummy proof
    const messageHash = ethers.utils.keccak256("0x5678");

    await VoiceAuth.register(wallet, currentENS, ZKPCommitment, voiceFeatures);

    // Set the dummy verifier to return true (proof is valid)
    await DummyZKPVerifier.setVerificationResult(true);

    await VoiceAuth.recover(wallet, newENS, zkProof, messageHash);

    const updatedData = await VoiceAuth.voiceDataMapping(wallet);
    expect(updatedData.currentENS).to.equal(newENS);
    expect(updatedData.ZKPCommitment).to.equal(ZKPCommitment);
    expect(ethers.utils.hexlify(updatedData.voiceFeatures)).to.equal(ethers.utils.hexlify(voiceFeatures));
  });

  it("should not allow the same message hash to be used twice", async function () {
    const wallet = await accounts[0].getAddress();
    const currentENS = "example1.eth";
    const newENS1 = "example2.eth";
    const newENS2 = "example3.eth";
    const ZKPCommitment = ethers.utils.keccak256("0x1234");
    const voiceFeatures = ethers.utils.randomBytes(32);
    const zkProof = ethers.utils.randomBytes(192); // Dummy proof
    const messageHash = ethers.utils.keccak256("0x5678");

    await VoiceAuth.register(wallet, currentENS, ZKPCommitment, voiceFeatures);

    // Set the dummy verifier to return true (proof is valid)
    await DummyZKPVerifier.setVerificationResult(true);

    // First recovery using messageHash
    await VoiceAuth.recover(wallet, newENS1, zkProof, messageHash);

    // Second recovery using the same messageHash should fail
    await expect(VoiceAuth.recover(wallet, newENS2, zkProof, messageHash)).to.be.revertedWith("Message hash already used");
    });
});