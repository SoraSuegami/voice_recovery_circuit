import { ethers } from "hardhat";
import { Signer, Contract } from "ethers";
import { expect } from "chai";
import * as fs from "fs/promises";
import { AbiCoder } from "@ethersproject/abi";


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
    VoiceKeyRecover = await VoiceFactory.deploy(maxMsgSize);
    await VoiceKeyRecover.deployed();
    console.log(VoiceKeyRecover.address);
  });

  it("should register voice data", async function () {
    const wallet = (await ethers.getSigners())[0];
    const user = (await ethers.getSigners())[1];
    const input = JSON.parse(await fs.readFile("./test_data/evm_public_input.json", "utf-8"));
    await VoiceKeyRecover.connect(wallet).registerOwner(user.address);
    expect(await VoiceKeyRecover.connect(wallet).getOwner()).to.equal(user.address);
    await VoiceKeyRecover.connect(user).registerVoiceOfWallet(wallet.address, input.feature_hash, input.commitment_hash, input.commitment);
    const registeredData = await VoiceKeyRecover.voiceDataOfWallet(wallet.address);
    expect(registeredData.featureHash).to.equal(input.feature_hash);
    expect(registeredData.commitmentHash).to.equal(input.commitment_hash);
    expect(ethers.utils.hexlify(registeredData.commitment)).to.equal(ethers.utils.hexlify(input.commitment));
  });

  it("should recover and update the owner address", async function () {
    const wallet = (await ethers.getSigners())[0];
    const user0 = (await ethers.getSigners())[1];
    const user1 = (await ethers.getSigners())[2];;
    const input = JSON.parse(await fs.readFile("./test_data/evm_public_input.json", "utf-8"));
    await VoiceKeyRecover.connect(wallet).registerOwner(user0.address);
    await VoiceKeyRecover.connect(user0).registerVoiceOfWallet(wallet.address, input.feature_hash, input.commitment_hash, input.commitment);
    const proof = await fs.readFile("./test_data/evm_proof.hex", "utf-8");
    await VoiceKeyRecover.connect(user1).recover(wallet.address, input.message_hash, proof);
    expect(await VoiceKeyRecover.connect(wallet).getOwner()).to.equal(user1.address);
  });
});