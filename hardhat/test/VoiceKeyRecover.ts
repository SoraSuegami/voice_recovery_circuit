import { ethers } from "hardhat";
import { Signer, Contract } from "ethers";
import { expect } from "chai";
import * as fs from "fs/promises";


describe("VoiceKeyRecover", function () {
  let accounts: Signer[];
  let VoiceKeyRecover: Contract;

  beforeEach(async function () {
    // const signer = (await ethers.getSigners())[0];
    // console.log(await signer.getBalance());
    // const yulVerifier = await fs.readFile("./test_data/verifier_code.txt");
    // const wordSize = 32;
    const maxMsgSize = 64;

    // const factory = ethers.ContractFactory.fromSolidity(
    //   { bytecode: yulVerifier, abi: [] },
    //   signer
    // );
    // const contract = await factory.deploy({ gasLimit: 900_000_000 });
    // await contract.deployed();
    // console.log(contract.address);

    const VoiceFactory = await ethers.getContractFactory("VoiceKeyRecover");
    VoiceKeyRecover = await VoiceFactory.deploy(maxMsgSize, { gasLimit: 15771336 });
    await VoiceKeyRecover.deployed();
    console.log(VoiceKeyRecover.address);
  });

  it("should register voice data", async function () {
    const signer = (await ethers.getSigners())[0];
    const myAddr = signer.address;
    const input = JSON.parse(await fs.readFile("./test_data/public_input.json", "utf-8"));
    const commitment = input.commitment;
    const featureHash = input.featureHash;

    await VoiceKeyRecover.register(myAddr, commitment, featureHash);

    const registeredData = await VoiceKeyRecover.voiceDataMapping(myAddr);
    expect(registeredData.owner).to.equal(myAddr);
    expect(registeredData.featureHash).to.equal(featureHash);
    expect(ethers.utils.hexlify(registeredData.commitment)).to.equal(ethers.utils.hexlify(commitment));
  });

  // it("should recover and update ENS", async function () {
  //   const wallet = await accounts[0].getAddress();
  //   const currentENS = "example1.eth";
  //   const newENS = "example2.eth";
  //   const ZKPCommitment = ethers.utils.keccak256("0x1234");
  //   const voiceFeatures = ethers.utils.randomBytes(32);
  //   const zkProof = ethers.utils.randomBytes(192); // Dummy proof
  //   const messageHash = ethers.utils.keccak256("0x5678");

  //   await VoiceAuth.register(wallet, currentENS, ZKPCommitment, voiceFeatures);

  //   // Set the dummy verifier to return true (proof is valid)
  //   await DummyZKPVerifier.setVerificationResult(true);

  //   await VoiceAuth.recover(wallet, newENS, zkProof, messageHash);

  //   const updatedData = await VoiceAuth.voiceDataMapping(wallet);
  //   expect(updatedData.currentENS).to.equal(newENS);
  //   expect(updatedData.ZKPCommitment).to.equal(ZKPCommitment);
  //   expect(ethers.utils.hexlify(updatedData.voiceFeatures)).to.equal(ethers.utils.hexlify(voiceFeatures));
  // });

  // it("should not allow the same message hash to be used twice", async function () {
  //   const wallet = await accounts[0].getAddress();
  //   const currentENS = "example1.eth";
  //   const newENS1 = "example2.eth";
  //   const newENS2 = "example3.eth";
  //   const ZKPCommitment = ethers.utils.keccak256("0x1234");
  //   const voiceFeatures = ethers.utils.randomBytes(32);
  //   const zkProof = ethers.utils.randomBytes(192); // Dummy proof
  //   const messageHash = ethers.utils.keccak256("0x5678");

  //   await VoiceAuth.register(wallet, currentENS, ZKPCommitment, voiceFeatures);

  //   // Set the dummy verifier to return true (proof is valid)
  //   await DummyZKPVerifier.setVerificationResult(true);

  //   // First recovery using messageHash
  //   await VoiceAuth.recover(wallet, newENS1, zkProof, messageHash);

  //   // Second recovery using the same messageHash should fail
  //   await expect(VoiceAuth.recover(wallet, newENS2, zkProof, messageHash)).to.be.revertedWith("Message hash already used");
  // });
});