const { startRegistration, startAuthentication, browserSupportsWebAuthnAutofill } = SimpleWebAuthnBrowser;

function setStatus(text, type = 'info') {
  const statusEl = document.getElementById('status');
  statusEl.style.display = 'block';
  statusEl.className = `status-${type}`;
  statusEl.textContent = text;
}

function showDashboard(userData) {
  const card = document.querySelector('.card');
  card.innerHTML = `
    <div style="text-align: center; padding: 1rem 0;">
      <div style="font-size: 3rem; margin-bottom: 1rem;">🎉</div>
      <h1 style="color: #4ade80; margin-bottom: 0.5rem;">Authenticated!</h1>
      <p style="color: #94a3b8; font-size: 1rem;">Welcome, <strong style="color: #fff;">${userData.username}</strong>.</p>

      <div style="background: #0f172a; padding: 1rem; border-radius: 8px; margin: 1.5rem 0; text-align: left; font-size: 0.85rem; border: 1px solid #334155;">
        <p style="margin: 0 0 0.5rem 0; color: #38bdf8; font-weight: bold;">Server Verified Session Data:</p>
        <p style="margin: 0.25rem 0; color: #cbd5e1;">✓ Credential Type: <strong>${userData.authMethod}</strong></p>
        <p style="margin: 0.25rem 0; color: #cbd5e1;">✓ Total Payload Transferred: <strong>${userData.totalPayloadBytes} bytes</strong> (Signature)</p>
        <p style="margin: 0.25rem 0; color: #cbd5e1;">✓ Phishing Protection: <strong>${userData.phishingProtected ? 'ACTIVE' : 'INACTIVE'} (${userData.verifiedRPID})</strong></p>
        <p style="margin: 0.25rem 0; color: #4ade80;">✓ Password / Shared Secret Sent: <strong>${userData.passwordBytesSent} bytes</strong></p>
      </div>

      <button class="btn btn-secondary" onclick="window.location.reload()">Sign Out</button>
    </div>
  `;
}

// 1. REGISTRATION
async function registerPasskey() {
  const username = document.getElementById('username').value;
  if (!username) return alert('Please enter a username');

  try {
    setStatus('1. Requesting WebAuthn registration options...', 'info');

    const startRes = await fetch('/api/register-start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    const { options } = await startRes.json();

    setStatus('Prompting hardware authenticator / password manager...', 'info');
    const attResp = await startRegistration(options);

    setStatus('Sending attestation to server for verification...', 'info');
    const finishRes = await fetch('/api/register-finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, response: attResp })
    });

    if (finishRes.ok) {
      setStatus('✅ Passkey created & saved! You can now sign in.', 'success');
    } else {
      setStatus('❌ Registration failed.', 'error');
    }
  } catch (err) {
    setStatus(`❌ Error: ${err.message || 'Cancelled'}`, 'error');
  }
}

// 2. USERNAME-LESS LOGIN
// Pass response data to showDashboard
async function loginPasskey(useAutofill = false) {
  try {
    if (!useAutofill) setStatus('Requesting challenge from server...', 'info');

    const startRes = await fetch('/api/login-start', { method: 'POST' });
    const { options } = await startRes.json();

    if (!useAutofill) setStatus('Prompting Passkey selection...', 'info');

    const asseResp = await startAuthentication(options, useAutofill);

    setStatus('Verifying signature on server...', 'info');
    const finishRes = await fetch('/api/login-finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ response: asseResp })
    });

    const result = await finishRes.json();

    if (finishRes.ok) {
      // Pass server-verified metadata directly
      showDashboard(result.user);
    } else {
      setStatus('❌ Authentication failed.', 'error');
    }
  } catch (err) {
    if (!useAutofill) setStatus(`❌ Error: ${err.message || 'Cancelled'}`, 'error');
  }
}

// Start Conditional UI (Autofill overlay) on load
window.addEventListener('DOMContentLoaded', async () => {
  if (await browserSupportsWebAuthnAutofill()) {
    loginPasskey(true);
  }
});
