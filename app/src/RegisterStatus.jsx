import { Typography } from "@mui/material";
import React from "react";

export default function RegisterStatus({ registerStatus }) {
  return (
    <div width="100%">
      {registerStatus !== null && 0 <= registerStatus && (
        <p>
          <Typography component="span" variant="h5">
            Creating commitment...
            {registerStatus >= 2 && (
              <Typography component="span" variant="h5" color="green">
                Success
              </Typography>
            )}
            {registerStatus === 1 && (
              <Typography component="span" variant="h5" color="error">
                Error
              </Typography>
            )}
          </Typography>
        </p>
      )}
      {3 <= registerStatus && (
        <p>
          <Typography component="span" variant="h5">
            Sending commitment...
            {registerStatus === 5 && (
              <Typography component="span" variant="h5" color="green">
                Success
              </Typography>
            )}
            {registerStatus === 4 && (
              <Typography component="span" variant="h5" color="error">
                Error
              </Typography>
            )}
          </Typography>
        </p>
      )}
    </div>
  );
}
