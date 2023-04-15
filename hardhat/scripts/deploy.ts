import { ethers } from "hardhat";

async function main() {
  // Get the contract factory
  const ENSDeployer = await ethers.getContractFactory('ENSDeployer');

  // Deploy the contract
  console.log('Deploying ENSDeployer...');
  const ensDeployer = await ENSDeployer.deploy();
  await ensDeployer.deployed();
  console.log('ENSDeployer deployed to:', ensDeployer.address);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});