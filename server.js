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

// Global in-memory storage for presentation demo
const users = {};        // username -> { id, passkeys: [] }
const passkeyStore = {}; // credentialID -> { username, publicKey, counter }
const challenges = {};   // challenge store

// High-contrast colors with a bold neon-green twist optimized for Light Mode & Projectors
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  register: '\x1b[1;\x1b[38;5;129m',  // Bold Electric Neon Purple/Magenta (#AF00FF)
  login:    '\x1b[1;\x1b[38;5;33m',  // Bold Electric Cyan/Blue (#0087FF)
  border: '\x1b[1;\x1b[34m',          // Bold Dark Blue for heavy frame borders
  header: '\x1b[1;\x1b[34m',          // Bold Dark Blue for titles
  detail: '\x1b[1;\x1b[30m',          // Bold Black for technical subheaders
  success: '\x1b[1;\x1b[38;5;34m',    // High-saturation Vivid Emerald/Neon Green
  error: '\x1b[1;\x1b[31m'            // Bold Dark Red for errors
};

const line = '═'.repeat(95);
function logHeader(step, title, color = C.header) {
  console.log(`\n${C.border}${line}${C.reset}`);
  console.log(`${color}[SERVER LOG] STEP ${step}: ${title}${C.reset}`);
  console.log(`${C.border}${line}${C.reset}`);
}

// --- 1. REGISTRATION START ---
app.post('/api/register-start', async (req, res) => {
  const { username } = req.body;
  logHeader(1, `[REGISTER] INITIATING PASSKEY REGISTRATION FOR USER: "${username}"`, C.register);

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
      residentKey: 'required',
      userVerification: 'preferred',
    },
  });

  challenges[username] = options.challenge;

  console.log(`  ${C.detail}[TECHNICAL DETAIL] Generated Public Key Creation Options:${C.reset}`);
  console.log(`  ├── Cryptographic Challenge (Random Nonce): ${options.challenge}`);
  console.log(`  ├── Relying Party ID (Origin Domain): ${options.rp.id}`);
  console.log(`  └── Resident Key Requirement: REQUIRED (Enables username-less login)`);

  res.json({ options });
});

// --- 2. REGISTRATION FINISH ---
app.post('/api/register-finish', async (req, res) => {
  const { username, response } = req.body;
  logHeader(2, `[REGISTER] VERIFYING ATTESTATION STATEMENT FOR USER: "${username}"`, C.register);

  const user = users[username];
  if (!user) return res.status(400).json({ error: 'User session not found' });

  const clientData = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64').toString('utf-8'));

  console.log(`  ${C.detail}[TECHNICAL DETAIL] Decoded Client Data JSON from Client:${C.reset}`);
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

    logHeader(3, `[REGISTER] REGISTRATION SUCCESSFUL - PUBLIC KEY STORED`, C.register);
    console.log(`  ├── Credential ID: ${credential.id}`);
    console.log(`  ├── Asymmetric Public Key Size: ${credential.publicKey.length} bytes`);
    console.log(`${C.success}  └── [SUCCESS] Public key stored${C.reset}`);

    return res.json({ status: 'ok' });
  }

  res.status(400).json({ error: 'Attestation verification failed' });
});

// --- 3. LOGIN START (USERNAME-LESS / DISCOVERABLE) ---
app.post('/api/login-start', async (req, res) => {
  logHeader(1, `[LOGIN] INITIATING AUTHENTICATION REQUEST`, C.login);

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'preferred',
  });

  challenges['global_auth'] = options.challenge;

  console.log(`  ${C.detail}[TECHNICAL DETAIL] Generated Authentication Request Options:${C.reset}`);
  console.log(`  ├── Cryptographic Challenge: ${options.challenge}`);
  console.log(`  └── Allowed Credentials: [EMPTY] (Requesting authenticator to list local passkeys)`);

  res.json({ options });
});

// --- 4. LOGIN FINISH ---
app.post('/api/login-finish', async (req, res) => {
  const { response } = req.body;
  logHeader(2, `[LOGIN] VERIFYING SIGNATURE FROM CREDENTIAL ID: ${response.id}`, C.login);

  const rawBodyString = JSON.stringify(req.body);
  const payloadSizeBytes = Buffer.byteLength(rawBodyString);

  const passkey = passkeyStore[response.id];

  if (!passkey) {
    console.log(`${C.error}  └── [ERROR] Unknown Credential ID. Passkey not found in server DB.${C.reset}`);
    return res.status(400).json({ error: 'Unknown credential. Please register first.' });
  }

  console.log(`  └── Matched Credential ID to DB User: "${passkey.username}"`);

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

    logHeader(3, `[LOGIN] CRYPTOGRAPHIC VERIFICATION SUCCESSFUL`, C.login);
    console.log(`  ├── Total Network Payload Received: ${payloadSizeBytes} bytes`);
    console.log(`${C.success}  └── [SUCCESS] User "${passkey.username}" authenticated via Public Key Cryptography${C.reset}`);

    return res.json({
      status: 'ok',
      user: {
        username: passkey.username,
        authMethod: response.type,
        totalPayloadBytes: payloadSizeBytes,
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
  console.log(`${C.border}${line}${C.reset}`);
  console.log(`${C.success} PASSKEY DEMO RUNNING AT http://localhost:3000${C.reset}`);
  console.log(`${C.border}${line}${C.reset}\n`);
});
