import { ethers } from "hardhat";
import * as fs from "fs/promises";

async function main() {
  const signer = (await ethers.getSigners())[0];
  console.log(await signer.getBalance());
  const yulVerifier = await fs.readFile("./test_data/verifier_code.txt");
  const wordSize = 32;
  const maxMsgSize = 64;

  // const factory = ethers.ContractFactory.fromSolidity(
  //   { bytecode: yulVerifier, abi: [] },
  //   signer
  // );
  // const contract = await factory.deploy({ gasLimit: 9000000000000000, gasPrice: 875000000 });
  // await contract.deployed();
  // console.log(contract.address);
  const VerifierInternalFactory = await ethers.getContractFactory("VerifierInternal");
  const VerifierInternal = await VerifierInternalFactory.deploy();
  await VerifierInternal.deployed();
  console.log(VerifierInternal.address);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
