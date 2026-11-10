# Passkey Demo

A small demo app that visualizes the passkey (WebAuthn / FIDO2) registration and authentication flow.

The browser UI lets you register a passkey and sign in with it. Meanwhile, the Node.js server prints a color-coded, step-by-step log of what happens on the server side (challenges, client data, credential IDs, signature verification, etc.).

## Features

- **Passkey registration** with a username (creates a discoverable credential / resident key).
- **Username-less sign-in** using discoverable credentials, including conditional UI (autofill) where the browser supports it.
- **Verbose server logging** that explains each step of the flow in the terminal.
- A success screen that shows server-verified data (credential type, payload size, RP ID / phishing protection).

## Tech stack

- [Express](https://expressjs.com/) 5 for the HTTP server and static file hosting
- [`@simplewebauthn/server`](https://simplewebauthn.dev/) for WebAuthn verification on the server
- [`@simplewebauthn/browser`](https://simplewebauthn.dev/) v14 on the client, installed from npm and served locally by Express at `/vendor/simplewebauthn/`
- Plain HTML/JS front end, with no build step

## Prerequisites

- [Node.js](https://nodejs.org/) 20 or newer (required by `@simplewebauthn/server` v14; the project also uses ES modules)
- npm
- A browser with WebAuthn/passkey support, such as a current Chrome, Edge, Safari, or Firefox
- A passkey provider, such as a password manager (for example Proton Pass), your OS's built-in authenticator, or a hardware security key

## Run locally

```bash
# 1. Install dependencies
npm install

# 2. Start the server
npm start
```

`npm start` runs `node server.js`.

### Verbose server log

By default the server log shows only the key steps of the flow. For the full technical detail (key algorithms, attestation format, AAGUID, UV flag, device type, backup state, signature counter, and so on), start the server in verbose mode:

```bash
npm run start:verbose   # same as: node server.js -v
```

Then open <http://localhost:3000> in your browser.

> Use `localhost` exactly as shown. The relying party ID (`localhost`) and origin (`http://localhost:3000`) are hard-coded in `server.js`, so accessing the app via `127.0.0.1` or another hostname will make WebAuthn verification fail.


## How to use

1. Enter a username (the default is `in4210`) and click **Register New Passkey**. Follow your browser or OS prompt to create the passkey.
2. Click **Sign in with Passkey** and choose the passkey you just created.
3. Watch the terminal where the server is running to see each step of the flow logged (add `-v` for more detail, see [Verbose server log](#verbose-server-log)).

## Project structure

```
.
├── server.js         # Express server and WebAuthn registration/login endpoints
├── public/
│   ├── index.html    # UI
│   └── app.js        # Client-side WebAuthn logic
└── package.json
```

### API endpoints

| Method | Path                    | Purpose                                      |
| ------ | ----------------------- | -------------------------------------------- |
| POST   | `/api/register-start`   | Generate registration options and a challenge |
| POST   | `/api/register-finish`  | Verify the attestation and store the public key |
| POST   | `/api/login-start`      | Generate authentication options (no username) |
| POST   | `/api/login-finish`     | Verify the signature and authenticate the user |

## Limitations

This is a demo, not production code:

- Users, passkeys, and challenges are stored **in memory only** and are lost whenever the server restarts. A passkey registered in your browser will no longer be recognized after a restart.
- The login challenge is a single global value, so concurrent sign-ins are not supported.
- The RP ID, origin, and port (`3000`) are hard-coded.

- There are no sessions or real authorization. A successful login only renders a confirmation screen.
