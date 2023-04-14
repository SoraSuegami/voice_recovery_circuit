import React, { useState, useEffect } from 'react';
import urlJoin from 'url-join';
import './App.css';

const apiUrl = "http://127.0.0.1:5000"

function App() {
  const [data, setData] = useState(null);

  useEffect(() => {
    (async () => {
      const url = urlJoin(apiUrl, '/api/data')
      console.log(url)
      const response = await fetch(urlJoin(apiUrl, '/api/data'));
      const data = await response.json();
      setData(data);
    })()
  }, []);

  return (
    <div>
      {data ? (
        <div>
          <p>Name: {data.name}</p>
          <p>Age: {data.age}</p>
        </div>
      ) : (
        <p>Loading...</p>
      )}
    </div>
  );
}

export default App;