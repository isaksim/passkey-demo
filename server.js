import express from 'express';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';

const app = express();
app.use(express.json());
app.use(express.static('public'));

const RP_NAME = 'Passkey Demo';
const RP_ID = 'localhost';
const ORIGIN = 'http://localhost:3000';

// Global in-memory storage for the demo
const users = {};        // username -> { id, passkeys: [] }
const passkeyStore = {}; // credentialID -> { username, publicKey, counter }
const challenges = {};   // challenge store

function logHeader(step, title) {
  console.log('\n\x1b[36m%s\x1b[0m', `================================================================================`);
  console.log('\x1b[33m%s\x1b[0m', `[SERVER LOG] STEP ${step}: ${title.toUpperCase()}`);
  console.log('\x1b[36m%s\x1b[0m', `================================================================================`);
}

// --- 1. REGISTRATION START ---
app.post('/api/register-start', async (req, res) => {
  const { username } = req.body;
  logHeader(1, `Initiating Passkey Registration for User: "${username}"`);

  if (!users[username]) {
    users[username] = { id: username, passkeys: [] };
  }
  const user = users[username];

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: new TextEncoder().encode(user.id),
    userName: username,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'required', // Mandates creating a Discoverable Credential
      userVerification: 'preferred',
    },
  });

  challenges[username] = options.challenge;

  console.log('  [TECHNICAL DETAIL] Generated Public Key Creation Options:');
  console.log(`  ├── Cryptographic Challenge (Random Nonce): ${options.challenge}`);
  console.log(`  ├── Relying Party ID (Origin Domain): ${options.rp.id}`);
  console.log(`  └── Resident Key Requirement: REQUIRED (Enables username-less login)`);

  res.json({ options });
});

// --- 2. REGISTRATION FINISH ---
app.post('/api/register-finish', async (req, res) => {
  const { username, response } = req.body;
  logHeader(2, `Verifying Attestation Statement for User: "${username}"`);

  const user = users[username];
  if (!user) return res.status(400).json({ error: 'User session not found' });

  const clientData = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64').toString('utf-8'));

  console.log('  [TECHNICAL DETAIL] Decoded Client Data JSON from Client:');
  console.log(`  ├── Type: ${clientData.type}`);
  console.log(`  ├── Challenge Match: ${clientData.challenge === challenges[username] ? 'MATCHED ✓' : 'FAILED ✗'}`);
  console.log(`  └── Origin: ${clientData.origin}`);

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: challenges[username],
    expectedOrigin: ORIGIN,
    expectedRPID: RP_ID,
  });

  if (verification.verified && verification.registrationInfo) {
    const { credential } = verification.registrationInfo;

    const passkeyData = {
      username,
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter ?? 0,
    };

    user.passkeys.push(passkeyData);
    passkeyStore[credential.id] = passkeyData;

    logHeader(3, `Registration Successful - Public Key Stored`);
    console.log(`  ├── Credential ID: ${credential.id}`);
    console.log(`  ├── Asymmetric Public Key Size: ${credential.publicKey.length} bytes`);
    console.log(`  ├── Initial Sign Counter: ${credential.counter}`);
    console.log('\x1b[32m%s\x1b[0m', '  └── [SECURITY GUARANTEE] The Private Key never left the user hardware/password manager!');

    return res.json({ status: 'ok' });
  }

  res.status(400).json({ error: 'Attestation verification failed' });
});

// --- 3. LOGIN START (USERNAME-LESS / DISCOVERABLE) ---
app.post('/api/login-start', async (req, res) => {
  logHeader(1, `Initiating Username-less Authentication Request`);

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'preferred',
  });

  challenges['global_auth'] = options.challenge;

  console.log('  [TECHNICAL DETAIL] Generated Authentication Request Options:');
  console.log(`  ├── Cryptographic Challenge: ${options.challenge}`);
  console.log(`  └── Allowed Credentials: [EMPTY] (Requesting authenticator to list local passkeys)`);

  res.json({ options });
});

// --- 4. LOGIN FINISH ---
app.post('/api/login-finish', async (req, res) => {
  const { response } = req.body;
  logHeader(2, `Verifying Signature from Credential ID: ${response.id}`);

  // Calculate total network payload size
  const rawBodyString = JSON.stringify(req.body);
  const payloadSizeBytes = Buffer.byteLength(rawBodyString);

  // Programmatically inspect the payload for password/secret keys
  const sensitiveKeys = ['password', 'pass', 'secret', 'pwd', 'authToken'];
  let detectedPasswordBytes = 0;

  sensitiveKeys.forEach((key) => {
    if (req.body[key]) {
      detectedPasswordBytes += Buffer.byteLength(String(req.body[key]));
    }
  });

  // Look up user based on Credential ID returned by authenticator
  const passkey = passkeyStore[response.id];

  if (!passkey) {
    console.log('\x1b[31m%s\x1b[0m', '  └── [ERROR] Unknown Credential ID. Passkey not found in server DB.');
    return res.status(400).json({ error: 'Unknown credential. Please register first.' });
  }

  console.log(`  ├── Matched Credential ID to DB User: "${passkey.username}"`);

  let pubKey = passkey.publicKey;
  if (!(pubKey instanceof Uint8Array) && typeof pubKey === 'object') {
    pubKey = new Uint8Array(Object.values(pubKey));
  }

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: challenges['global_auth'],
    expectedOrigin: ORIGIN,
    expectedRPID: RP_ID,
    credential: {
      id: passkey.id,
      publicKey: pubKey,
      counter: passkey.counter ?? 0,
    },
  });

  if (verification.verified) {
    const { authenticationInfo } = verification;
    passkey.counter = authenticationInfo.newCounter;

    logHeader(3, `Cryptographic Verification Successful`);
    console.log(`  ├── Total Network Payload Received: ${payloadSizeBytes} bytes`);
    console.log(`  ├── Password/Secret Keys Detected: ${detectedPasswordBytes} bytes`);
    console.log('\x1b[32m%s\x1b[0m', `  └── [SUCCESS] User "${passkey.username.toUpperCase()}" authenticated via Public Key Cryptography!`);

    return res.json({
      status: 'ok',
      user: {
        username: passkey.username,
        authMethod: response.type, // Directly returns 'public-key' from browser payload
        totalPayloadBytes: payloadSizeBytes,
        passwordBytesSent: detectedPasswordBytes,
        verifiedRPID: authenticationInfo.rpID || RP_ID,
        verifiedOrigin: authenticationInfo.origin || ORIGIN,
        phishingProtected: verification.verified
      }
    });
  }

  res.status(400).json({ error: 'Signature verification failed' });
});

app.listen(3000, () => {
  console.clear();
  console.log('\x1b[32m%s\x1b[0m', '================================================================================');
  console.log('\x1b[32m%s\x1b[0m', ' PASSKEY DEMO RUNNING AT http://localhost:3000');
  console.log('\x1b[32m%s\x1b[0m', '================================================================================\n');
});
