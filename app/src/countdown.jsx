import React, { useState, useEffect } from 'react';

export default function Countdown({sec, onCountdownEnd}) {
  const [seconds, setSeconds] = useState(null);

  useEffect(() => {
    setSeconds(sec)
    const interval = setInterval(() => {
      setSeconds(seconds => seconds - 1);
    }, 1000);
    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (seconds === 0 && onCountdownEnd) {
        onCountdownEnd();
    }
  }, [seconds, onCountdownEnd]);

  return (
    <span>
      {seconds}
    </span>
  );
}