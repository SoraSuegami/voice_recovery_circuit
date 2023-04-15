import { ethers } from "hardhat";
import { ENS__factory } from "../typechain";

async function main() {
  const accounts = await ethers.getSigners();
  console.log('Account:', accounts[0].address);

  // Get the ENS factory
  const ENSDeployer = await ethers.getContractFactory('ENSDeployer');

  // Deploy ENS
  console.log('Deploying ENSDeployer...');
  const ensDeployer = await ENSDeployer.deploy();
  await ensDeployer.deployed();
  console.log('ENSDeployer deployed to:', ensDeployer.address);

  // console.log('Register ENS address...');
  // const ensRegistryAddress = await ensDeployer.ens();
  // const ensRegistry = ENS__factory.connect(ensRegistryAddress, accounts[0]);

  // Deploy VoiceKeyRecover
  console.log('Deploying VoiceKeyRecover...');
  const voiceKeyRecover = await ethers.getContractFactory('VoiceKeyRecover');
  // await voiceKeyRecover.deploy(dummyVerifierAddress, ensDeployer.address, 32, 64);
  const vk = await voiceKeyRecover.deploy(ensDeployer.address, 32, 64);
  console.log('VoiceKeyRecover deployed to:', vk.address);

}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});