import React from "react";
import urlJoin from "url-join";
import "./App.css";
import RecordButton from "./RecordButton";
import { Typography } from "@mui/material";

const apiUrl = "http://127.0.0.1:5000";

function App() {
  const handleSendWav = async (blob) => {
    const url = urlJoin(apiUrl, "/api/upload-wav");
    const formData = new FormData();
    formData.append("file", blob);
    const response = await fetch(url, { method: "POST", body: formData });
    console.log(response);

    return response;
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
      <RecordButton sendToFlask={handleSendWav} />
    </div>
  );
}

export default App;
