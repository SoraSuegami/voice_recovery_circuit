// import { ethers } from "hardhat";
// import { Signer, Contract } from "ethers";
// import { expect } from "chai";
// import * as fs from "fs/promises";
// import { AbiCoder } from "@ethersproject/abi";


// describe("DemoContractWallet", function () {
//     let accounts: Signer[];
//     let VoiceKeyRecover: Contract;
//     let DemoContractWallet: Contract;

//     beforeEach(async function () {
//         const maxMsgSize = 64;

//         const VoiceFactory = await ethers.getContractFactory("VoiceKeyRecover");
//         VoiceKeyRecover = await VoiceFactory.deploy(maxMsgSize);
//         await VoiceKeyRecover.deployed();
//         let vkrAddr = VoiceKeyRecover.address;
//         const DemoFactory = await ethers.getContractFactory("DemoContractWallet");
//         DemoContractWallet = await DemoFactory.deploy(vkrAddr);
//         await DemoContractWallet.deployed();
//     });

//     it("should register the voice and recover", async function () {
//         const user0 = (await ethers.getSigners())[0];
//         const testValue = 20000;
//         await DemoContractWallet.connect(user0).depositEth({ value: testValue })
//         expect(await DemoContractWallet.connect(user0).getEthBalance()).to.equal(testValue);
//         expect(await DemoContractWallet.provider.getBalance(DemoContractWallet.address)).to.equal(testValue);
//         console.log(await DemoContractWallet.provider.getBalance(DemoContractWallet.address));
//         const transferValue = 100;
//         await DemoContractWallet.connect(user0).transferEth(user0.address, transferValue);
//         expect(await DemoContractWallet.connect(user0).getEthBalance()).to.equal(testValue - transferValue);
//         const input = JSON.parse(await fs.readFile("./test_data/demo_evm_public_input.json", "utf-8"));
//         await VoiceKeyRecover.connect(user0).registerVoiceOfWallet(DemoContractWallet.address, input.feature_hash, input.commitment_hash, input.commitment);
//         const proof = await fs.readFile("./test_data/demo_evm_proof.hex", "utf-8");
//         const user1 = (await ethers.getSigners())[1];
//         console.log(await VoiceKeyRecover.connect(user1).getMessageOfRecover(DemoContractWallet.address));
//         const tx = await VoiceKeyRecover.connect(user1).recover(DemoContractWallet.address, input.message_hash, proof);
//         const receipt = await tx.wait();
//         const gasCost = receipt.gasUsed;
//         console.log(`gas ${gasCost}`);
//         expect(await DemoContractWallet.connect(user1).getEthBalance()).to.equal(testValue - transferValue);
//         await DemoContractWallet.connect(user1).transferEth(user0.address, transferValue);
//         expect(await DemoContractWallet.connect(user1).getEthBalance()).to.equal(testValue - 2 * transferValue);
//     });
// });