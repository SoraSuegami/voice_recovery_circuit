import React, { useState, useRef } from "react";
import MicIcon from "@mui/icons-material/Mic";
import IconButton from "@mui/material/IconButton";
import MediaStreamRecorder from "msr";

const record_duration =1000;

// eslint-disable-next-line react/prop-types
function RecordButton({ sendRecording, ...props }) {
  const [recording, setRecording] = useState(false);
  const mediaRecorder = useRef(null);

  const startRecording = () => {
    navigator.mediaDevices
      .getUserMedia({ audio: true })
      .then((stream) => {
        mediaRecorder.current = new MediaStreamRecorder(stream);
        mediaRecorder.current.mimeType = "audio/wav"
        mediaRecorder.current.audioChannels = 1;
        mediaRecorder.current.sampleRate = 16000;
        mediaRecorder.current.start(record_duration); // 5秒ごとにデータを取得する
        setRecording(true);

        mediaRecorder.current.ondataavailable = (blob) => {
          // 5秒経過したら録音を停止する
          stopRecording();
          sendRecording(blob);
        };
      })
      .catch((err) => {
        console.log("録音が開始できませんでした: ", err);
      });
  };

  const stopRecording = () => {
    if (mediaRecorder.current) {
      mediaRecorder.current.stop();
      setRecording(false);
    }
  };

  return (
    <IconButton disabled={recording} onClick={startRecording}>
      <MicIcon
        disabled={recording}
        style={{
          fontSize: 80,
        }}
      />
    </IconButton>
  );
}

export default RecordButton;
