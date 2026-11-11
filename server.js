import express from 'express';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { COSEALG, cose, decodeCredentialPublicKey } from '@simplewebauthn/server/helpers';

// Run with `node server.js -v` (or `npm run start:verbose`) for the detailed server log
const VERBOSE = process.argv.includes('-v') || process.argv.includes('--verbose');

const app = express();
app.use(express.json());
app.use(express.static('public'));
// Serve the browser-side WebAuthn library locally so the demo works offline
app.use('/vendor/simplewebauthn', express.static('node_modules/@simplewebauthn/browser/dist/bundle'));

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
  register: '\x1b[1;38;5;129m',  // Bold Electric Neon Purple/Magenta (#AF00FF)
  login:    '\x1b[1;38;5;33m',   // Bold Electric Cyan/Blue (#0087FF)
  border: '\x1b[1;34m',          // Bold Dark Blue for heavy frame borders
  header: '\x1b[1;34m',          // Bold Dark Blue for titles
  detail: '\x1b[1;30m',          // Bold Black for technical subheaders
  success: '\x1b[1;38;5;34m',    // High-saturation Vivid Emerald/Neon Green
  error: '\x1b[1;31m'            // Bold Dark Red for errors
};

const line = '═'.repeat(95);
function logHeader(step, title, color = C.header) {
  console.log(`\n${C.border}${line}${C.reset}`);
  console.log(`${color}[SERVER LOG] STEP ${step}: ${title}${C.reset}`);
  console.log(`${C.border}${line}${C.reset}`);
}

// Prints rows as a tree. A row is [label, value] or [label, value, true]; the third form is
// verbose-only and is skipped unless -v is given. The last row (or `closing`, if given) gets └──.
function logTree(items, closing = null) {
  const rows = items.filter(([, , verboseOnly]) => !verboseOnly || VERBOSE);
  rows.forEach(([label, value], i) => {
    const isLast = !closing && i === rows.length - 1;
    console.log(`  ${isLast ? '└──' : '├──'} ${label}: ${value}`);
  });
  if (closing) console.log(`  └── ${closing}`);
}

function logDetail(title) {
  console.log(`  ${C.detail}[TECHNICAL DETAIL] ${title}${C.reset}`);
}

function logFailure(message) {
  console.log(`  ${C.error}✗ [ERROR] ${message}${C.reset}`);
}

const fromBase64Url = (value) => Buffer.from(value, 'base64url');
const decodeClientData = (response) =>
  JSON.parse(fromBase64Url(response.response.clientDataJSON).toString('utf-8'));
const matchLabel = (actual, expected) => (actual === expected ? 'MATCHED ✓' : `FAILED ✗ (expected ${expected})`);

// --- 1. REGISTRATION START ---
app.post('/api/register-start', async (req, res) => {
  const { username } = req.body;
  logHeader('1–2', `[REGISTER] INITIATE REGISTRATION → CREATION OPTIONS FOR USER: "${username}"`, C.register);

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

  const selection = options.authenticatorSelection ?? {};

  logDetail('Creation Options sent to the browser:');
  logTree([
    ['Cryptographic Challenge (Random Nonce)', options.challenge],
    ['Relying Party ID (Origin Domain)', options.rp.id],
    ['Relying Party Name', options.rp.name, true],
    ['User', `${options.user.name} (user handle, base64url: ${options.user.id})`, true],
    ['Accepted Key Algorithms', options.pubKeyCredParams.map(({ alg }) => COSEALG[alg] ?? `COSE ${alg}`).join(', '), true],
    ['Resident Key Requirement', `${selection.residentKey ?? 'not set'} (enables username-less login)`, true],
    ['User Verification', selection.userVerification ?? 'not set', true],
    ['Attestation Requested', options.attestation, true],
    ['Timeout', `${options.timeout} ms`, true],
  ], VERBOSE ? "Challenge stored, waiting for the client's response (STEP 5)…" : null);

  res.json({ options });
});

// --- 2. REGISTRATION FINISH ---
app.post('/api/register-finish', async (req, res) => {
  const { username, response } = req.body;
  logHeader(5, `[REGISTER] REGISTER PUBLIC KEY FOR USER: "${username}"`, C.register);

  const user = users[username];
  const expectedChallenge = challenges[username];
  if (!user || !expectedChallenge) {
    logFailure('No registration in progress for this user (call register-start first).');
    return res.status(400).json({ error: 'User session not found' });
  }

  let clientData;
  try {
    clientData = decodeClientData(response);
  } catch (err) {
    logFailure(`Could not decode clientDataJSON: ${err.message}`);
    return res.status(400).json({ error: 'Malformed registration response' });
  }

  logDetail('Decoded Client Data JSON from Client:');
  logTree([
    ['Type', clientData.type, true],
    ['Challenge (client data vs. issued)', matchLabel(clientData.challenge, expectedChallenge)],
    ['Origin', `${clientData.origin} — ${matchLabel(clientData.origin, ORIGIN)}`],
  ]);

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });
  } catch (err) {
    logFailure(`Registration verification failed: ${err.message}`);
    return res.status(400).json({ error: 'Attestation verification failed' });
  }

  if (verification.verified && verification.registrationInfo) {
    const {
      credential, fmt, aaguid, userVerified,
      credentialDeviceType, credentialBackedUp, origin, rpID,
    } = verification.registrationInfo;

    const passkeyData = {
      username,
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter ?? 0,
    };

    user.passkeys.push(passkeyData);
    passkeyStore[credential.id] = passkeyData;

    // Only present because generateRegistrationOptions() requests the credProps extension
    const discoverable = response.clientExtensionResults?.credProps?.rk;
    const aaguidIsEmpty = /^[0-]+$/.test(aaguid);

    logDetail('Stored Credential:');
    const publicKeyB64 = Buffer.from(credential.publicKey).toString('base64url');

    logTree([
      ['Credential ID', credential.id],
      ['Public Key (as stored)', `${publicKeyB64.slice(0, 32)}…`],
      ['Fields in Stored Passkey Record', Object.keys(passkeyData).join(', ')],
      ['Asymmetric Public Key Size', `${credential.publicKey.length} bytes`, true],
      ['Verified Origin / RP ID', `${origin} / ${rpID}`, true],
      ['Attestation Format', fmt === 'none' ? 'none (no attestation statement, authenticator model is not attested)' : fmt, true],
      ['AAGUID', aaguidIsEmpty ? `${aaguid} (authenticator did not identify its model)` : aaguid, true],
      ['Authenticator Attachment', response.authenticatorAttachment ?? 'not reported', true],
      ['Transports', credential.transports?.join(', ') || 'not reported', true],
      ['User Verified (UV flag)', userVerified ? 'yes' : 'no', true],
      ['Credential Device Type', `${credentialDeviceType}${credentialDeviceType === 'multiDevice' ? ' (can be synced/backed up)' : ''}`, true],
      ['Backed Up', credentialBackedUp ? 'yes' : 'no', true],
      ['Discoverable (resident key)', discoverable === undefined ? 'not reported by browser' : (discoverable ? 'yes' : 'no'), true],
      ['Signature Counter', credential.counter ?? 0, true],
    ], `${C.success}[SUCCESS] Only public data is stored on the server (no password, no private key)${C.reset}`);

    return res.json({ status: 'ok' });
  }

  logFailure('Registration response could not be verified.');
  res.status(400).json({ error: 'Attestation verification failed' });
});

// --- 3. LOGIN START (USERNAME-LESS / DISCOVERABLE) ---
app.post('/api/login-start', async (req, res) => {
  logHeader('1–2', `[LOGIN] INITIATE LOGIN → REQUEST OPTIONS`, C.login);

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'preferred',
  });

  challenges['global_auth'] = options.challenge;

  const allowed = options.allowCredentials?.length ?? 0;

  logDetail('Request Options sent to the browser:');
  logTree([
    ['Cryptographic Challenge', options.challenge],
    ['Relying Party ID', options.rpId, true],
    ['User Verification', options.userVerification, true],
    ['Allowed Credentials', allowed === 0
      ? '[EMPTY] (Requesting authenticator to list local passkeys)'
      : `${allowed} credential(s) listed`, true],
    ['Timeout', `${options.timeout} ms`, true],
    ['Passkeys Registered on This Server', Object.keys(passkeyStore).length, true],
  ], VERBOSE ? "Challenge stored, waiting for the client's signed response (STEP 5)…" : null);

  res.json({ options });
});

// --- 4. LOGIN FINISH ---
app.post('/api/login-finish', async (req, res) => {
  const { response } = req.body;
  logHeader(5, `[LOGIN] VERIFY ASSERTION RESPONSE (CREDENTIAL ID: ${response?.id})`, C.login);

  if (!response?.id) {
    logFailure('Request did not contain an authentication response.');
    return res.status(400).json({ error: 'Malformed authentication response' });
  }

  // Size of the request body as it came over the wire
  const payloadSizeBytes =
    Number(req.headers['content-length']) || Buffer.byteLength(JSON.stringify(req.body));

  const passkey = passkeyStore[response.id];

  if (!passkey) {
    logFailure('Unknown Credential ID. Passkey not found in server DB.');
    return res.status(400).json({ error: 'Unknown credential. Please register first.' });
  }

  const expectedChallenge = challenges['global_auth'];

  let clientData;
  try {
    clientData = decodeClientData(response);
  } catch (err) {
    logFailure(`Could not decode clientDataJSON: ${err.message}`);
    return res.status(400).json({ error: 'Malformed authentication response' });
  }

  // For discoverable credentials the authenticator returns the user handle we set at registration
  const userHandle = response.response.userHandle
    ? fromBase64Url(response.response.userHandle).toString('utf-8')
    : null;

  logDetail('Decoded Client Data JSON from Client:');
  logTree([
    ['Type', clientData.type, true],
    ['Challenge (client data vs. issued)', matchLabel(clientData.challenge, expectedChallenge)],
    ['Origin', `${clientData.origin} — ${matchLabel(clientData.origin, ORIGIN)}`],
    ['Matched Credential ID to DB User', `"${passkey.username}"`],
    ['User Handle returned by authenticator', userHandle === null
      ? 'none returned'
      : `"${userHandle}" ${userHandle === passkey.username ? '(matches DB user ✓)' : '(does NOT match DB user ✗)'}`, true],
    ['Stored Public Key', `${passkey.publicKey.length} bytes`, true],
    ['Stored Signature Counter', passkey.counter ?? 0, true],
  ]);

  let pubKey = passkey.publicKey;
  if (!(pubKey instanceof Uint8Array) && typeof pubKey === 'object') {
    pubKey = new Uint8Array(Object.values(pubKey));
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: passkey.id,
        publicKey: pubKey,
        counter: passkey.counter ?? 0,
      },
    });
  } catch (err) {
    logFailure(`Authentication verification failed: ${err.message}`);
    return res.status(400).json({ error: 'Signature verification failed' });
  }

  if (verification.verified) {
    const { authenticationInfo } = verification;
    const previousCounter = passkey.counter ?? 0;
    passkey.counter = authenticationInfo.newCounter;

    const counterNote = previousCounter === 0 && authenticationInfo.newCounter === 0
      ? ' (authenticator does not use a signature counter, common for synced passkeys)'
      : '';
    const { credentialDeviceType } = authenticationInfo;

    // Real value: algorithm read from the stored public key
    const signatureAlg = decodeCredentialPublicKey(pubKey).get(cose.COSEKEYS.alg);

    logDetail('Verification Result:');
    logTree([
      ['Signature', `VALID ✓ (${COSEALG[signatureAlg] ?? `COSE ${signatureAlg}`}, verified with the stored public key)`],
      ['Total Network Payload Received', `${payloadSizeBytes} bytes`, true],
      ['Verified Origin / RP ID', `${authenticationInfo.origin} / ${authenticationInfo.rpID}`],
      ['User Verified (UV flag)', authenticationInfo.userVerified ? 'yes' : 'no', true],
      ['Credential Device Type', `${credentialDeviceType}${credentialDeviceType === 'multiDevice' ? ' (can be synced/backed up)' : ''}`, true],
      ['Backed Up', authenticationInfo.credentialBackedUp ? 'yes' : 'no', true],
      ['Signature Counter', `${previousCounter} → ${authenticationInfo.newCounter}${counterNote}`, true],
    ], `${C.success}[SUCCESS] User "${passkey.username}" authenticated via Public Key Cryptography${C.reset}`);

    return res.json({
      status: 'ok',
      user: {
        username: passkey.username,
        authMethod: response.type,
        verifiedRPID: authenticationInfo.rpID,
        verifiedOrigin: authenticationInfo.origin,
        // The library only reports success if the signed origin and RP ID matched what we expect
        phishingProtected: authenticationInfo.origin === ORIGIN && authenticationInfo.rpID === RP_ID
      }
    });
  }

  logFailure('Signature could not be verified.');
  res.status(400).json({ error: 'Signature verification failed' });
});

app.listen(3000, () => {
  console.clear();
  console.log(`${C.border}${line}${C.reset}`);
  console.log(`${C.success} PASSKEY DEMO RUNNING AT http://localhost:3000${VERBOSE ? ' (verbose logging)' : ''}${C.reset}`);
  console.log(`${C.border}${line}${C.reset}\n`);
});
