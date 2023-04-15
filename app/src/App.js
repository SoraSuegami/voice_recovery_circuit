import React, { useEffect, useState } from "react";
import urlJoin from "url-join";
import "./App.css";
import RecordButton from "./RecordButton";
import VoiceKeyRecovery from "./contracts/VoiceKeyRecover.sol/VoiceKeyRecover.json";
import { Typography, Box, Card, CardContent, Modal, TextField } from "@mui/material";
import { ethers } from "ethers";
import RegisterStatus from "./RegisterStatus";
import Countdown from "./countdown";
import { countOnes } from "./util";

const contractAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const apiUrl = "http://127.0.0.1:5000";
const threshold = 64;

function App() {
  const [vk, setVk] = useState(null);
  const [sender, setSender] = useState(null);
  const [isRecording, setIsRecording] = useState(false);
  const [hashEcc, setHashRcc] = useState(null);
  const [codeErrorCount, setCodeErrorCount] = useState(null);
  const [featXorEcc, setFeatXorEcc] = useState(null);
  const [recoveredHashEcc, setRecoveredHashEcc] = useState(null);
  const [proof, setProof] = useState(null);
  const [hashFeatXorEcc, setHashFeatXorEcc] = useState(null);

  // 0: commitment生成中,  1: commitment生成失敗, 2: commitment生成完了,3: commitment送信中,  4: commitment送信失敗 ,5: commitment送信完了,
  console.log(isRecording);
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
          setHashFeatXorEcc(commitmentData.hashCommitment);
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

  const longTextSx = {
    marginBottom: 2,
    width: "100%",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
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
          const vk = new ethers.Contract(
            contractAddress,
            VoiceKeyRecovery.abi,
            signer
          );
          console.log(VoiceKeyRecovery.abi);
          await checkRegistered(vk, sender);

          setVk(vk);
          console.log("initialized!");
          setIsRecording(false);

          // vk.on("Registered", () => {
          //   checkRegistered(vk, sender);
          // }).catch((err) => {
          //   throw err;
          // });

          return () => {
            vk.removeAllListeners();
          };
        }
      } catch (err) {
        console.error("Error initializing contract or provider:", err);
      }
    })();
  }, [checkRegistered, sender]);

  const handleKeyRegisterWav = async (blob) => {
    setIsRecording(false);
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
    console.log(data);
    setRegisterStatus(2);
    if (vk) {
      setRegisterStatus(3);
      await vk
        .register(
          sender,
          data.hash_ecc,
          data.hash_feat_xor_ecc,
          data.feat_xor_ecc
        )
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
    setIsRecording(false);
    // Commitment生成開始
    const url = urlJoin(apiUrl, "/api/gen-proof");
    const formData = new FormData();
    formData.append("file", blob, "recorded_audio.wav");

    const jsonData = {
      hash_ecc: hashEcc,
      feat_xor_ecc: featXorEcc,
      msg: "0x9a8f43",
    };
    formData.append("jsonData", JSON.stringify(jsonData));
    const response = await fetch(url, { method: "POST", body: formData });
    const data = await response.json().catch((err) => {
      throw err;
    });
    console.log(data);
    // console.log(countOnes(data.code_error));
    setCodeErrorCount(countOnes(data.code_error));
    setRecoveredHashEcc(data.recovered_hash_ecc);
    setProof(data.proof)

    if (vk) {
      await vk
        // TODO: not sender, but from form
        .recover(sender, data.hash_ecc_msg, data.proof)
        .catch((err) => {
          throw err;
        });
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
      {registered ? (
        <Card>
          <CardContent sx={CardContentStyle}>
            <Typography variant="h4" component="h1" sx={{ marginBottom: 2 }}>
              Recover Your Key
            </Typography>
            <RecordButton
              sendRecording={handleKeyRecoverWav}
              disabled={isRecording}
              setDisabled={setIsRecording}
            />
            {codeErrorCount !== null && (
              <>
                error bit count: {codeErrorCount} is less then threshold:{" "}
                {threshold}
              </>
            )}
            <Box component="p" width="80%">
              <Typography variant="h6" sx={longTextSx}>
                c = <br/>{featXorEcc}
              </Typography>
              <Typography variant="h6" sx={longTextSx}>
                h_W = <br/>{hashEcc}
              </Typography>
              {recoveredHashEcc && (
                <Typography
                  variant="h6"
                  color={hashEcc === recoveredHashEcc ? "green" : "error"}
                  sx={longTextSx}
                >
                  recovered h_W = <br/>{recoveredHashEcc}
                </Typography>
              )}
            </Box>
            <Box display="flex" justifyContent="center" alignItems="center"><Typography variant="h6" mr={2}>0x</Typography>
            <TextField value={sender} onChange={(e)=>setSender(e.target.value)} width = "100%" label="Put your (wallet contract) account here" variant="outlined"/>
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
              disabled={isRecording}
              setDisabled={setIsRecording}
            />
            <RegisterStatus registerStatus={registerStatus} />
            <Box display="flex" justifyContent="center" alignItems="center"><Typography variant="h6" mr={2}>0x</Typography>
            <TextField value={sender} onChange={(e)=>setSender(e.target.value)} width = "100%" label="Put your (wallet contract) account here" variant="outlined"/>
            </Box>
          </CardContent>
        </Card>
      )}
      <Modal
        open={isRecording}
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
              Please read the following text. <br />
              (recording...{isRecording && <Countdown sec={5} />} s)
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
