const { startRegistration, startAuthentication, browserSupportsWebAuthnAutofill } = SimpleWebAuthnBrowser;

// Conditional UI (passkey autofill) is opt-in: open http://localhost:3000/?autofill
const AUTOFILL_ENABLED = new URLSearchParams(window.location.search).has('autofill');

function setStatus(text, type = 'info') {
  const statusEl = document.getElementById('status');
  statusEl.style.display = 'block';
  statusEl.className = `status-${type}`;
  statusEl.textContent = text;
}

// Escape values before they are placed into innerHTML (the username is user-controlled input)
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showDashboard(userData) {
  const card = document.querySelector('.card');
  card.innerHTML = `
    <div style="text-align: center; padding: 1rem 0;">
      <h1 style="color: #16a34a; margin-bottom: 0.5rem;">Authenticated</h1>
      <p style="color: #475569; font-size: 1rem;">Welcome, <strong style="color: #0f172a;">${escapeHtml(userData.username)}</strong>.</p>

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
    const attResp = await startRegistration({ optionsJSON: options });

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

    const asseResp = await startAuthentication({ optionsJSON: options, useBrowserAutofill: useAutofill });

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
    // In autofill mode the request is a silent background one, so don't show errors for it
    if (!useAutofill) setStatus(`❌ Error: ${err.message || 'Cancelled'}`, 'error');
  }
}

// Start Conditional UI (passkey suggestions in the username field) on load, only with ?autofill
if (AUTOFILL_ENABLED) {
  window.addEventListener('DOMContentLoaded', async () => {
    // The "webauthn" token is what lets the browser offer passkeys in this field
    document.getElementById('username').setAttribute('autocomplete', 'username webauthn');

    if (await browserSupportsWebAuthnAutofill()) {
      loginPasskey(true);
    }
  });
}
