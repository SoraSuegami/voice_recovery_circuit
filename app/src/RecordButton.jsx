import React, { useState } from "react";
import MicIcon from "@mui/icons-material/Mic";
import IconButton from "@mui/material/IconButton";

// eslint-disable-next-line react/prop-types
function RecordButton({ sendToFlask, ...props }) {
  const [recording, setRecording] = useState(false);

  const startRecording = () => {
    navigator.mediaDevices
      .getUserMedia({ audio: true })
      .then((stream) => {
        const mediaRecorder = new MediaRecorder(stream);
        const chunks = [];

        mediaRecorder.start();

        mediaRecorder.addEventListener("dataavailable", (event) => {
          chunks.push(event.data);
        });

        mediaRecorder.addEventListener("stop", () => {
          const blob = new Blob(chunks, { type: "audio/wav" });
          setRecording(false);
          sendToFlask(blob);
        });

        setTimeout(() => {
          mediaRecorder.stop();
        }, 5000);

        setRecording(true);
      })
      .catch((error) => console.error(error));
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
