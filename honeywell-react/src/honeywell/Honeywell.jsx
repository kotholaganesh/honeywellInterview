import React, { useState } from 'react';
import honeywell from '../assets/honeywell.png';

function Honeywell() {
    const [encryptInput, setencryptInput] = useState('');
    const [decryptInput, setdecryptInput] = useState('');
    const [output, setOutput] = useState('');
    const [out, setOut] = useState('');

    const handleSubmitEncrypt = async (event) => {
        event.preventDefault();
        const response = await fetch('http://localhost:8080/api/encrypt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(encryptInput),
        });
        const data = await response.text();
        setOutput(data);
    };

    const handleSubmitDecrypt = async (event) => {
        event.preventDefault();
        const response = await fetch('http://localhost:8080/api/decrypt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(decryptInput),
        });
        const data = await response.text();
        setOut(data);
    };

    return (
        <div className="App">
            <header>
                <img
                    src={honeywell} // Set the source of the image  
                    alt="Honeywell Logo" // Alt text for accessibility  
                    style={{ width: '200px' }} // Adjust the size as needed  
                />
                <h1>Welcome to Encrypt and Decrypt Application</h1>
            </header>

            <h1>String Encrypt</h1>
            <form onSubmit={handleSubmitEncrypt}>
                <input
                    type="text"
                    value={encryptInput}
                    onChange={(e) => setencryptInput(e.target.value)}
                    placeholder="Enter a string"
                />
                <button type="submit">Encrypt</button>
            </form>
            {output && <h2>Encrypt String: {output}</h2>}

            <h1>String Decrypt</h1>
            <form onSubmit={handleSubmitDecrypt}>
                <input
                    type="text"
                    value={decryptInput}
                    onChange={(e) => setdecryptInput(e.target.value)}
                    placeholder="Enter a string"
                />
                <button type="submit">Decrypt</button>
            </form>
            {out && <h2>Decrypt String: {out}</h2>}
        </div>
    );
}

export default Honeywell;  