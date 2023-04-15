import React, { useEffect, useState } from "react";
import urlJoin from "url-join";
import "./App.css";
import RecordButton from "./RecordButton";
import VoiceKeyRecovery from "./contracts/VoiceKeyRecover.sol/VoiceKeyRecover.json";
import { Typography, Box, Card, CardContent, Modal } from "@mui/material";
import { ethers } from "ethers";
import RegisterStatus from "./RegisterStatus";
import Countdown from "./countdown";

const contractAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const apiUrl = "http://127.0.0.1:5000";

function App() {
  const [vk, setVk] = useState(null);
  const [sender, setSender] = useState(null);
  const [recordDisabled, setRecordDisabled] = useState(true);
  const [hashEcc, setHashRcc] = useState(null);
  const [featXorEcc, setFeatXorEcc] = useState(null);
  // 0: commitment生成中,  1: commitment生成失敗, 2: commitment生成完了,3: commitment送信中,  4: commitment送信失敗 ,5: commitment送信完了,
  console.log(recordDisabled);
  const [registerStatus, setRegisterStatus] = useState(null);
  console.log("hashEcc: ", hashEcc, "featXorEcc: ", featXorEcc);

  const [registered, setRegistered] = useState(null);
  console.log("sender: ", sender);

  const checkRegistered = React.useCallback(
    async (vk, sender) => {
      if (vk) {
        const r = await vk.isRegistered(sender);
        console.log("registered: ", r);
        if (r) {
          if (registered === false) {
            alert("Your key is registered!");
          }
          const commitmentData = await vk.voiceDataOfWallet(sender);
          // console.log("commitmentData: ", commitmentData);
          setHashRcc(commitmentData.featureHash);
          setFeatXorEcc(commitmentData.commitment);
        }
        setRegistered(r);
      } else {
        console.error("VoiceKeyRecover contract not initialized yet");
      }
    },
    [registered]
  );

  const CardContentStyle = {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    maxWidth: "60vw",
    padding: 5,
    backgroundColor: "#f5f5f5",
  };

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
          await provider.send("eth_requestAccounts", []);
          signer = provider.getSigner();
          const sender = await signer.getAddress();
          setSender(sender);
          const vk = new ethers.Contract(
            contractAddress,
            VoiceKeyRecovery.abi,
            signer
          );
          console.log(VoiceKeyRecovery.abi);
          await checkRegistered(vk, sender);
          setVk(vk);
          console.log("initialized!");
          setRecordDisabled(false);

          vk.on("Registered", () => {
            checkRegistered(vk, sender);
          }).catch((err) => {
            throw err;
          });

          return () => {
            vk.removeAllListeners();
          };
        }
      } catch (err) {
        console.error("Error initializing contract or provider:", err);
      }
    })();
  }, [checkRegistered]);

  const handleKeyRegisterWav = async (blob) => {
    setRecordDisabled(false);
    // Commitment生成開始
    setRegisterStatus(0);
    const url = urlJoin(apiUrl, "/api/feature-vector");
    const formData = new FormData();
    formData.append("file", blob, "recorded_audio.wav");
    const response = await fetch(url, { method: "POST", body: formData });
    const data = await response.json().catch((err) => {
      setRegisterStatus(1);
      throw err;
    });
    setRegisterStatus(2);
    if (vk) {
      setRegisterStatus(3);
      await vk
        .register(sender, data.hash_ecc, data.feat_xor_ecc)
        .catch((err) => {
          setRegisterStatus(4);
          throw err;
        });
      setRegisterStatus(5);
    } else {
      console.error("VoiceKeyRecover contract not initialized yet");
    }
  };

  const handleKeyRecoverWav = async (blob) => {
    setRecordDisabled(false);
    console.log("unimplement!");
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
      {registered ? (
        <Card>
          <CardContent sx={CardContentStyle}>
            <Typography variant="h4" component="h1" sx={{ marginBottom: 2 }}>
              Recover Your Key
            </Typography>
            <RecordButton
              sendRecording={handleKeyRecoverWav}
              disabled={recordDisabled}
              setDisabled={setRecordDisabled}
            />
            <Box component="p" width="80%">
              <Typography
                variant="h6"
                sx={{ marginBottom: 2, overflowWrap: "break-word" }}
              >
                c = {featXorEcc}
              </Typography>
              <Typography
                variant="h6"
                sx={{ marginBottom: 2, overflowWrap: "break-word" }}
              >
                h_W = {hashEcc}
              </Typography>
            </Box>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent sx={CardContentStyle}>
            <Typography variant="h4" component="h1" sx={{ marginBottom: 2 }}>
              <p>You have not Registerd!</p>
              <p> Register Your Key</p>
            </Typography>
            <RecordButton
              sendRecording={handleKeyRegisterWav}
              disabled={recordDisabled}
              setDisabled={setRecordDisabled}
            />
            <RegisterStatus registerStatus={registerStatus} />
          </CardContent>
        </Card>
      )}
      <Modal
        open={recordDisabled}
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Card sx={{ p: 5 }}>
          <CardContent>
          <Typography variant="h6" marginBottom={2}>
            Please read the following text. <br/>(recording...{recordDisabled && <Countdown sec={5} />} s)
          </Typography>
          <Typography variant="p" color="red">
            The sun is shining and the birds are singing.
          </Typography>
          </CardContent>
        </Card>
      </Modal>
    </div>
  );
}

export default App;
