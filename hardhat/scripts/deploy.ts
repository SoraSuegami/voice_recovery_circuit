import { ethers } from "hardhat";

async function main() {
  const accounts = await ethers.getSigners();
  console.log('Account:', accounts[0].address);

  // Deploy VoiceKeyRecover
  console.log('Deploying VoiceKeyRecover...');
  const voiceKeyRecover = await ethers.getContractFactory('VoiceKeyRecover');
  // await voiceKeyRecover.deploy(dummyVerifierAddress, ensDeployer.address, 32, 64);
  const vk = await voiceKeyRecover.deploy(64);
  console.log('VoiceKeyRecover deployed to:', vk.address);

}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});