import React, { useEffect, useState } from "react";
import urlJoin from "url-join";
import "./App.css";
import RecordButton from "./RecordButton";
import VoiceKeyRecovery from "./contracts/VoiceKeyRecover.sol/VoiceKeyRecover.json";
import { Typography } from "@mui/material";
import { ethers } from "ethers";

const contractAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const apiUrl = "http://127.0.0.1:5000";

function App() {
  const [vk, setVk] = useState(null);
  const [sender, setSender] = useState(null);
  console.log("sender: ", sender)

  useEffect(() => {
    (async () => {
      try {
        let signer;
        let provider;
        if (window.ethereum == null) {
          console.log("MetaMask not installed; using read-only defaults");
          provider = ethers.getDefaultProvider();
        } else {
          provider = new ethers.providers.Web3Provider(window.ethereum);
          await provider.send('eth_requestAccounts', [])
          signer = provider.getSigner();
          setSender(await signer.getAddress());
        }
        const vk = new ethers.Contract(contractAddress, VoiceKeyRecovery.abi, signer);
        console.log(VoiceKeyRecovery.abi)
        setVk(vk);
        console.log("initialized!")
      } catch (err) {
        console.error("Error initializing contract or provider:", err);
      }
    })();
  }, []);

  const handleSendWav = async (blob) => {
    const url = urlJoin(apiUrl, "/api/feature-vector");
    const formData = new FormData();
    formData.append("file", blob, "recorded_audio.wav");
    const response = await fetch(url, { method: "POST", body: formData });
    const data = await response.json();

    // console.log(vk);
    if (vk) {
      // console.log("sender: ", sender, "hash_ecc: ", data.hash_ecc, "feat_xoc_ecc: ", data.feat_xor_ecc);
      await vk.register(sender, data.hash_ecc, data.feat_xor_ecc);
    } else {
      console.error("VoiceKeyRecover contract not initialized yet");
    }
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100vh",
        backgroundColor: "#f5f5f5",
      }}
    >
      <Typography variant="h4" component="h1" sx={{ marginBottom: 2 }}>
        Recover Your Key
      </Typography>
      <RecordButton sendRecording={handleSendWav} />
    </div>
  );
}

export default App;
