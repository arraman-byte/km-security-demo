(function () {
  const startBtn = document.getElementById('startBtn');
  const statusEl = document.getElementById('status');
  const userCodeEl = document.getElementById('userCode');
  const verificationEl = document.getElementById('verificationUri');
  const verificationCompleteEl = document.getElementById('verificationUriComplete');
  const codePanel = document.getElementById('codePanel');
  const resultPanel = document.getElementById('resultPanel');
  const resultEl = document.getElementById('result');

  function show(el) { el.style.display = ''; }
  function hide(el) { el.style.display = 'none'; }

  function renderTokenCard(title, decoded) {
    if (!decoded) return '';
    return `<div class="panel">
      <h3>${title}</h3>
      <p><span class="badge ${decoded.signatureValid ? 'good' : 'bad'}">${decoded.signatureValid ? 'signature valid' : 'signature not verified'}</span>
         <span class="badge ${decoded.expired ? 'warn' : 'good'}">${decoded.expired ? 'expired' : 'active'}</span></p>
      <h4 style="color:#94a3b8;">Header</h4>
      <pre>${escapeHtml(decoded.headerJson || '')}</pre>
      <h4 style="color:#94a3b8;">Claims</h4>
      <pre>${escapeHtml(decoded.claimsJson || '')}</pre>
      <h4 style="color:#94a3b8;">Raw</h4>
      <pre>${escapeHtml(decoded.raw || '')}</pre>
    </div>`;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
  }

  async function poll(deviceCode, interval) {
    while (true) {
      await new Promise(r => setTimeout(r, interval * 1000));
      const form = new URLSearchParams({ device_code: deviceCode });
      const resp = await fetch('/demo/device-code/poll', { method: 'POST', body: form });
      const data = await resp.json();
      if (data.status === 'pending') {
        statusEl.textContent = 'Waiting for user to authorize... (oauth error: ' + data.oauthError + ')';
        if (data.oauthError === 'slow_down') interval += 5;
        continue;
      }
      if (data.status === 'done') {
        statusEl.textContent = 'Authorized! Tokens received.';
        hide(codePanel);
        show(resultPanel);
        resultEl.innerHTML =
          renderTokenCard('ID Token', data.idToken) +
          renderTokenCard('Access Token', data.accessToken) +
          renderTokenCard('Refresh Token', data.refreshToken);
        return;
      }
      statusEl.textContent = 'Error: ' + (data.oauthError || data.message || 'unknown');
      return;
    }
  }

  startBtn.addEventListener('click', async () => {
    statusEl.textContent = 'Requesting device code...';
    hide(resultPanel);
    const resp = await fetch('/demo/device-code/start', { method: 'POST' });
    const data = await resp.json();
    if (data.error) {
      statusEl.textContent = 'Start failed: ' + data.error + ' - ' + (data.message || '');
      return;
    }
    userCodeEl.textContent = data.user_code;
    verificationEl.textContent = data.verification_uri;
    verificationEl.href = data.verification_uri;
    if (data.verification_uri_complete) {
      verificationCompleteEl.textContent = data.verification_uri_complete;
      verificationCompleteEl.href = data.verification_uri_complete;
      verificationCompleteEl.parentElement.style.display = '';
    }
    show(codePanel);
    statusEl.textContent = 'Open the verification URL in another tab and enter the user_code. Polling every '
      + data.interval + 's...';
    poll(data.device_code, data.interval || 5);
  });
})();
