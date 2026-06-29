/**
 * ============================================================
 * auth.js — Portable Authentication Module
 * ============================================================
 *
 * Provides three account types for any web app:
 *   - Guest     : local-only, no sync, no credentials
 *   - Token     : 128-bit cryptographic token, KV-synced
 *   - Google    : Google OAuth via GIS, KV-synced
 *
 * One-way upgrade path: Guest → Token or Google, Token → Google.
 * Google accounts cannot be downgraded.
 *
 * TOKEN MIGRATION: legacy tokens generated with Math.random()
 * are detected at boot and offered an upgrade. Secondary devices
 * auto-migrate silently via a server-side forwarding pointer.
 *
 * ── INTEGRATION CHECKLIST ────────────────────────────────────
 *
 * 1. SCRIPT TAG — add to <head> before your app script:
 *
 *      <script src="https://accounts.google.com/gsi/client" async
 *              onload="window.gisReady=true;window.dispatchEvent(new Event('gis-ready'))">
 *      </script>
 *
 * 2. HTML MODAL — add to your HTML (can be empty body, JS fills it):
 *
 *      <div class="modal-overlay" id="modal-account-setup" role="dialog">
 *        <div class="modal modal-sm">
 *          <div class="modal-header">
 *            <h2 class="modal-title" id="account-setup-title"></h2>
 *          </div>
 *          <div class="modal-body" id="account-setup-body"></div>
 *        </div>
 *      </div>
 *
 * 3. SETTINGS MODAL — add the auth section inside your settings modal
 *    (see AUTH_README.md for the full HTML block).
 *
 * 4. CSS — copy the auth section from auth.css (or AUTH_README.md)
 *    into your stylesheet. Uses CSS custom properties — map them to
 *    your own design tokens or override directly.
 *
 * 5. INIT — call Auth.init(config) before your app's boot sequence:
 *
 *      Auth.init({
 *        googleClientId: 'YOUR_CLIENT_ID.apps.googleusercontent.com',
 *        storageKey:     'myapp_appdata',         // localStorage key for app data
 *        storageAuthKey: 'myapp_google_id_token', // localStorage key for Google token
 *        storageDismissKey: 'myapp_token_upgrade_dismissed',
 *        workerBase:     () => myApp.getWorkerUrl(),
 *        getData:        () => myApp.data,
 *        setData:        (d) => { myApp.data = d; myApp.save(); },
 *        mergeData:      (raw) => myApp.mergeData(raw),    // merge raw KV data with defaults
 *        onSignedIn:     (data, isNew) => myApp.onSignedIn(data, isNew),
 *        onGuestReady:   (data) => myApp.render(data),
 *        onSessionExpired: () => {},  // optional — module calls showGoogleReauth() automatically
 *        pushToWorker:   () => myApp.pushToWorker(),
 *        startSyncPing:  () => myApp.startSyncPing(),
 *        openModal:      (id) => myApp.openModal(id),
 *        closeModal:     (id) => myApp.closeModal(id),
 *        toast:          (msg) => myApp.toast(msg),
 *        appName:        'My App',                // shown in wizard copy
 *        appEmoji:       '🎯',                    // shown in welcome toast
 *      });
 *
 * 6. BOOT — in your DOMContentLoaded handler, call:
 *
 *      await Auth.bootCheck();   // handles session verify + legacy migration
 *
 * 7. SETTINGS MODAL — in your openSettingsModal function, call:
 *
 *      Auth.renderSettingsSection();
 *
 * ── HOST APP INTERFACE ────────────────────────────────────────
 * The config object is the ONLY interface between this module and
 * your app. All functions below call into config — nothing is
 * hardcoded to a specific app's internals.
 *
 * Required config keys:
 *   googleClientId    string   — Google OAuth Client ID (null disables Google auth)
 *   storageKey        string   — localStorage key for the main data blob
 *   storageAuthKey    string   — localStorage key for the Google ID token
 *   storageDismissKey string   — localStorage key for token upgrade dismissed flag
 *   workerBase        function — returns the worker base URL string or ''
 *   getData           function — returns the current app data object
 *   setData           function — (data) sets and persists app data
 *   mergeData         function — (raw) merges raw KV JSON with app defaults, returns object
 *   onSignedIn        function — (data, isNewAccount) called after successful sign-in
 *   onGuestReady      function — (data) called when guest continues without account
 *   onSessionExpired  function — called when Google session expires at boot
 *   pushToWorker      function — pushes current data to worker, returns Promise<bool>
 *   startSyncPing     function — starts the periodic sync ping
 *   openModal         function — (id) opens a modal by DOM id
 *   closeModal        function — (id) closes a modal by DOM id
 *   toast             function — (message) shows a toast notification
 *
 * Optional config keys:
 *   appName           string   — app name shown in wizard (default: 'the app')
 *   appEmoji          string   — emoji shown in welcome toast (default: '🎉')
 * ============================================================
 */

const Auth = (() => {

  // ── Internal config store ───────────────────────────────────────
  // Populated by Auth.init(). Never access directly outside this module.
  let C = null;

  // ── Config accessors ────────────────────────────────────────────
  const cfg         = () => C;
  const workerBase  = () => (C.workerBase() || '').replace(/\/+$/, '');
  const getData     = () => C.getData();
  const appName     = () => C.appName  || 'the app';
  const appEmoji    = () => C.appEmoji || '🎉';

  // ── localStorage helpers ────────────────────────────────────────
  // Isolated to the configured keys so multiple apps can coexist.
  const store = {
    get:    (key)      => { try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : null; } catch { return null; } },
    set:    (key, val) => { try { localStorage.setItem(key, JSON.stringify(val)); } catch {} },
    remove: (key)      => { try { localStorage.removeItem(key); } catch {} },
  };

  // ── HMAC request signing (token accounts) ────────────────────────
  // Derives a signing key from the token via HKDF and signs every
  // worker request. The raw token never travels as a bare bearer
  // credential. Transparent to the user — no UX change.
  // Must match the derivation in auth-worker.js / worker.js exactly.

  async function _deriveHmacKey(token) {
    const enc    = new TextEncoder();
    const keyMat = await crypto.subtle.importKey(
      'raw', enc.encode(token), { name: 'HKDF' }, false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256',
        salt: enc.encode('rivulet-hmac-v1'),
        info: enc.encode('request-signing') },
      keyMat,
      { name: 'HMAC', hash: 'SHA-256' },
      false, ['sign']
    );
  }

  async function _signRequest(method, token, body) {
    const enc       = new TextEncoder();
    const timestamp = String(Date.now());
    const bodyHash  = Array.from(
      new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(body || '')))
    ).map(b => b.toString(16).padStart(2,'0')).join('');
    const message  = `${method.toUpperCase()}:${token}:${timestamp}:${bodyHash}`;
    const key      = await _deriveHmacKey(token);
    const sigBytes = await crypto.subtle.sign('HMAC', key, enc.encode(message));
    const sig      = btoa(String.fromCharCode(...new Uint8Array(sigBytes)))
      .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    return { 'X-Timestamp': timestamp, 'X-Signature': sig };
  }

  // _authHeaders(method, token, body) — returns the correct auth headers
  // for a worker request based on current account type.
  //   Google → Authorization: Bearer <idToken>
  //   Token  → X-Timestamp + X-Signature (HMAC)
  async function _authHeaders(method, token, body) {
    if(isGoogleAccount()) {
      const idToken = store.get(C.storageAuthKey);
      return idToken ? { 'Authorization': `Bearer ${idToken}` } : {};
    }
    try { return await _signRequest(method, token, body); } catch { return {}; }
  }

  // ── Token generation ─────────────────────────────────────────────
  // 16 random bytes → base64url → 22 chars, ~128 bits of entropy.
  // This is the account credential for token-auth accounts.
  function generateToken() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  // isLegacyToken() — detects tokens generated by the old Math.random()
  // method (≤16 chars). Used to offer the security upgrade prompt.
  function isLegacyToken(token) {
    return typeof token === 'string' && token.length <= 16;
  }

  // ── Account type checks ──────────────────────────────────────────
  // These read authMethod from the host app's data object via getData().

  // isGoogleAuthAvailable() — true only when googleClientId is configured.
  // Gates all Google sign-in UI — button never appears without a Client ID.
  function isGoogleAuthAvailable() {
    return typeof C?.googleClientId === 'string' && C.googleClientId.length > 0;
  }

  // isGoogleAccount() — true if the current account uses Google auth.
  function isGoogleAccount() {
    return getData()?.authMethod === 'google';
  }

  // isGuest() — true if the user hasn't created a real account yet.
  // Guest data is local-only; no worker sync, no token, no Google session.
  function isGuest() {
    const d = getData();
    return !d?.authMethod || d?.authMethod === 'guest';
  }

  // isTokenAccount() — true for standard token-based accounts.
  function isTokenAccount() {
    return getData()?.authMethod === 'token';
  }

  // ── GIS (Google Identity Services) readiness ─────────────────────
  // GIS loads via an async script tag. waitForGIS() resolves cleanly
  // whenever the library becomes available, with a 2-second fallback.
  // Add to <head>:
  //   <script src="https://accounts.google.com/gsi/client" async
  //           onload="window.gisReady=true;window.dispatchEvent(new Event('gis-ready'))">
  //   </script>
  function waitForGIS() {
    return new Promise(resolve => {
      if(window.gisReady && window.google?.accounts?.id) return resolve();
      window.addEventListener('gis-ready', resolve, { once: true });
      setTimeout(() => { if(window.google?.accounts?.id) resolve(); }, 2000);
    });
  }

  // ── Worker connectivity test ─────────────────────────────────────
  // Used by the wizard to confirm a Worker URL before enabling sign-in.
  // Returns true if the worker health check responds with 200.
  async function testWorkerUrl(url) {
    try {
      const res = await fetch(`${url.replace(/\/+$/, '')}/`, { method: 'GET' });
      return res.ok;
    } catch { return false; }
  }

  // ── handleGoogleCredential() ─────────────────────────────────────
  // Core handler called after GIS returns a credential JWT.
  // Flow:
  //   1. POST idToken to worker /auth/google for RS256 verification
  //   2. Worker returns { ok, kvKey, profile } — kvKey is "google:<sub>"
  //   3. Try to load existing data from kvKey
  //   4. If found: merge and call onSignedIn(data, false)
  //   5. If not found: use current data, set authMethod=google, call onSignedIn(data, true)
  //   6. Store idToken in localStorage for session verification at next boot
  //
  // Returns { ok, isNewAccount, profile } on success, null on failure.
  // HOST APP INTERFACE: calls getData(), setData(), mergeData(), onSignedIn(), pushToWorker()
  async function handleGoogleCredential(idToken) {
    const base = workerBase();
    if(!base) {
      C.toast('Set your Worker URL first.');
      return null;
    }

    // Step 1: verify token server-side
    let workerRes;
    try {
      const res = await fetch(`${base}/auth/google`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ idToken }),
      });
      workerRes = await res.json();
      if(!res.ok || !workerRes.ok) throw new Error(workerRes.error || 'Worker auth failed');
    } catch(err) {
      console.error('[Auth] handleGoogleCredential worker error:', err);
      return null;
    }

    const { kvKey, profile } = workerRes;
    const oldWorkerUrl = getData()?.workerUrl || '';

    // Step 2: try to load existing account from Google KV key
    let remote = null;
    try {
      const res = await fetch(`${base}/storage/${encodeURIComponent(kvKey)}/profile`, {
        headers: { 'Authorization': `Bearer ${idToken}` },
      });
      if(res.ok) { const j = await res.json(); remote = j.value ?? j; }
    } catch { /* new account — remote stays null */ }

    const isNewAccount = !remote;

    if(remote) {
      // Existing Google account — merge with defaults and apply
      const merged = C.mergeData(remote);
      merged.userToken    = kvKey; // always set — remote profile has no userToken field
      merged.workerUrl    = oldWorkerUrl || merged.workerUrl;
      merged.authMethod   = 'google';
      merged.linkedGoogle = profile;
      C.onSignedIn(merged, false);
    } else {
      // New Google account — update current data in place
      const d = getData();
      d.authMethod   = 'google';
      d.linkedGoogle = profile;
      d.userToken    = kvKey; // kvKey is "google:<sub>" — stable permanent ID
      d.workerUrl    = oldWorkerUrl;
      C.setData(d);
      C.onSignedIn(d, true);
    }

    // Store ID token for session verification at next boot
    store.set(C.storageAuthKey, idToken);

    return { ok: true, isNewAccount, profile };
  }

  // ── signInWithGoogle() ───────────────────────────────────────────
  // Renders a GIS button into buttonEl and resolves when sign-in completes.
  // ux_mode: 'popup' gives the familiar account-picker experience and will
  // transition naturally when Google enforces FedCM/passkeys universally.
  //
  // buttonEl: DOM element to render the Google button into (required).
  //           If null, falls back to One Tap prompt (often suppressed).
  //
  // Returns { ok, isNewAccount, profile } on success, null on cancel/fail.
  async function signInWithGoogle(buttonEl) {
    if(!isGoogleAuthAvailable()) {
      console.warn('[Auth] Google sign-in not available — googleClientId not set.');
      return null;
    }

    await waitForGIS();

    return new Promise(resolve => {
      google.accounts.id.initialize({
        client_id:   C.googleClientId,
        auto_select: false, // never auto-prompt — only show when explicitly triggered
        callback:    async (response) => {
          // Cancel any pending GIS prompt immediately after credential received.
          // Without this, GIS continues auto-prompting on subsequent interactions.
          google.accounts.id.cancel();
          const result = await handleGoogleCredential(response.credential);
          resolve(result);
        },
      });

      if(buttonEl) {
        // renderButton is reliable across all browsers.
        // One Tap is suppressed too often (Edge, Firefox, 3rd-party cookies
        // blocked) to use as primary — renderButton is always the right choice.
        google.accounts.id.renderButton(buttonEl, {
          theme:   'filled_black',
          size:    'large',
          width:   buttonEl.offsetWidth || 280,
          text:    'continue_with',
          locale:  'en',
          ux_mode: 'popup',
        });
      } else {
        // No element — fall back to One Tap
        google.accounts.id.prompt(notification => {
          if(notification.isSkippedMoment() || notification.isDismissedMoment()) {
            resolve(null);
          }
        });
      }
    });
  }

  // ── signOutGoogle() ──────────────────────────────────────────────
  // Revokes the Google session client-side and clears the stored token.
  // Does NOT delete account data — only clears the session credential.
  // HOST APP INTERFACE: calls getData(), setData()
  async function signOutGoogle() {
    if(!isGoogleAccount()) return;
    const d     = getData();
    const email = d.linkedGoogle?.email;
    if(window.google?.accounts?.id) {
      google.accounts.id.cancel();
      if(email) google.accounts.id.revoke(email, () => {});
    }
    store.remove(C.storageAuthKey);
    d.linkedGoogle = null;
    // Keep authMethod as 'google' — don't silently downgrade.
    // User must go through account setup to change auth method.
    C.setData(d);
    C.toast('Signed out. Your data is still stored securely.');
  }

  // ── verifyGoogleSession() ────────────────────────────────────────
  // Called at boot for Google accounts. First checks the stored JWT's
  // exp claim locally — no network needed if the token has >5 minutes
  // remaining. Only hits the worker when the token is near/past expiry.
  // Returns true if session is usable, false if re-auth is required.
  // HOST APP INTERFACE: calls getData(), setData(), workerBase()
  async function verifyGoogleSession() {
    if(!isGoogleAccount()) return false;
    const idToken = store.get(C.storageAuthKey);
    if(!idToken) return false;

    // Decode JWT payload locally to check exp — no signature verification,
    // just reading the expiry claim to avoid unnecessary network calls.
    try {
      const parts   = idToken.split('.');
      if(parts.length !== 3) return false;
      const payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
      const now     = Math.floor(Date.now() / 1000);
      const exp     = payload.exp || 0;

      // Token still has more than 5 minutes — accept without a network call
      if(exp - now > 5 * 60) return true;

      // Token is expired or nearly expired — re-verify via worker
      const base = workerBase();
      if(!base) return false;

      const res  = await fetch(`${base}/auth/verify`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ idToken }),
      });
      const data = await res.json();
      if(res.ok && data.ok) {
        if(data.profile) {
          const d = getData();
          d.linkedGoogle = data.profile;
          C.setData(d);
        }
        return true;
      }
      return false;
    } catch { return false; }
  }

  // ── bootCheck() ─────────────────────────────────────────────────
  // Call this from your DOMContentLoaded handler for existing sessions.
  // Handles two boot-time auth concerns:
  //
  //   1. Google session verification — if the account uses Google auth,
  //      verifies the stored ID token is still valid. If expired, calls
  //      onSessionExpired() so the host app can prompt re-auth.
  //      Returns false so the host app knows to stop the boot sequence.
  //
  //   2. Legacy token detection — if the token looks like it was generated
  //      by Math.random() (≤16 chars), shows a one-time upgrade prompt
  //      AFTER the worker pull resolves (so auto-migration via
  //      X-Token-Migrated header can suppress the prompt if it fires first).
  //
  // Call this AFTER your worker pull / data merge, passing the result:
  //   const remote = await myApp.pullFromWorker();
  //   const shouldContinue = await Auth.bootCheck(tokenBeforePull);
  //   if(!shouldContinue) return;
  //
  // tokenBeforePull: the userToken value captured BEFORE the worker pull,
  //   since pullFromWorker may swap the token via X-Token-Migrated.
  //
  // Returns true if boot should continue normally, false if auth needs
  // to handle something (session expired, re-auth required).
  async function bootCheck(tokenBeforePull) {
    const d = getData();

    // 1. Google session check
    if(isGoogleAccount()) {
      const valid = await verifyGoogleSession();
      if(!valid) {
        // Show targeted re-auth screen — skips full wizard, no worker URL needed
        setTimeout(() => showGoogleReauth(), 800);
        return false;
      }
    }

    // 2. Legacy token upgrade prompt
    if(isLegacyToken(d.userToken) && !store.get(C.storageDismissKey)) {
      setTimeout(showTokenUpgradePrompt, 800);
    }

    return true;
  }

  // ── showGoogleReauth() ───────────────────────────────────────────
  // Shown when a returning Google user's ID token has expired at boot.
  // Skips the full wizard — no worker URL field, no account choice.
  // Shows the user's name/picture from stored profile for recognition,
  // then presents just the Google button to re-authenticate.
  // On success, resumes the app normally without disrupting data.
  // HOST APP INTERFACE: calls getData(), startSyncPing(), closeModal()
  function showGoogleReauth() {
    const d       = getData();
    const name    = d.linkedGoogle?.name    || [d.firstName, d.lastName].filter(Boolean).join(' ') || '';
    const email   = d.linkedGoogle?.email   || '';
    const picture = d.linkedGoogle?.picture || '';

    setupScreen('Welcome Back', `
      <p class="f13 lh muted" style="margin-bottom:1.25rem;">
        ${picture || name
          ? 'Your session has expired. Sign in again to continue.'
          : 'This account has been upgraded to Google sign-in. Sign in with Google to continue.'}
      </p>
      ${picture || name ? `
        <div class="auth-google-info" style="margin-bottom:1.25rem;">
          ${picture ? `<img src="${_esc(picture)}" class="auth-google-avatar" alt="">` : ''}
          <div>
            ${name  ? `<div style="font-size:.85rem;font-weight:500;">${_esc(name)}</div>`  : ''}
            ${email ? `<div style="font-size:.78rem;opacity:.6;">${_esc(email)}</div>` : ''}
          </div>
        </div>` : ''}
      <div id="auth-reauth-container" style="width:100%;min-height:44px;"></div>
      <div id="auth-reauth-status"
           style="min-height:1.3rem;font-size:.82rem;margin-top:.5rem;color:var(--red,#c07070);">
      </div>
      <div class="row gap-8 mt-8" style="justify-content:flex-start;">
        <button class="btn btn-ghost btn-sm" id="auth-btn-reauth-different">
          Use a different account
        </button>
      </div>
    `);

    document.getElementById('auth-btn-reauth-different').addEventListener('click', () => {
      C.closeModal('modal-account-setup');
      showAccountSetup();
    });

    const container = document.getElementById('auth-reauth-container');
    const statusEl  = document.getElementById('auth-reauth-status');

    signInWithGoogle(container).then(result => {
      if(result?.ok) {
        C.closeModal('modal-account-setup');
        C.startSyncPing();
      } else {
        statusEl.textContent = 'Sign-in cancelled — try again or use a different account.';
      }
    });
  }

  // ── handlePullMigration() ────────────────────────────────────────
  // Call this inside your pullFromWorker() when the worker returns
  // an X-Token-Migrated header. Silently swaps the local token,
  // marks upgrade as dismissed, and fires a best-effort push back
  // under the new token to register this device as migrated.
  //
  // Usage in pullFromWorker():
  //   const migratedTo = res.headers.get('X-Token-Migrated');
  //   if(migratedTo) Auth.handlePullMigration(migratedTo, data);
  //
  // Returns the modified data object with the new token set.
  // HOST APP INTERFACE: calls getData(), setData(), workerBase()
  function handlePullMigration(newToken, data) {
    data.userToken = newToken;
    store.set(C.storageDismissKey, true);
    // Best-effort push back under the new token
    const base = (data.workerUrl || getData()?.workerUrl || '').replace(/\/+$/, '');
    if(base) {
      const bodyStr = JSON.stringify(data);
      _signRequest('PUT', newToken, bodyStr).catch(() => ({})).then(hmacHdrs => {
        fetch(`${base}/storage/${encodeURIComponent(newToken)}/profile`, {
          method:  'PUT',
          headers: { 'Content-Type': 'application/json', ...hmacHdrs },
          body:    bodyStr,
        }).catch(() => {}); // best-effort; sync ping will retry on failure
      });
    }
    C.toast('Account security upgraded automatically ✓');
    return data;
  }

  // ── renderSettingsSection() ─────────────────────────────────────
  // Call this from your openSettingsModal() function to update the
  // auth section of the settings modal based on current account type.
  //
  // Expects these element IDs in the settings modal HTML
  // (see AUTH_README.md for the full HTML block):
  //   settings-auth-badge       — pill showing account type
  //   settings-guest-section    — shown for guests
  //   settings-token-group      — shown for token accounts
  //   settings-google-info      — shown for Google accounts
  //   settings-worker-group     — hidden for guests
  //   settings-sync-controls    — hidden for guests
  //   settings-upgrade-google   — shown for token accounts when Google available
  //
  // HOST APP INTERFACE: reads getData() to determine current auth state
  function renderSettingsSection() {
    const d            = getData();
    const badgeEl      = document.getElementById('settings-auth-badge');
    const guestEl      = document.getElementById('settings-guest-section');
    const tokenEl      = document.getElementById('settings-token-group');
    const googleInfoEl = document.getElementById('settings-google-info');
    const workerEl     = document.getElementById('settings-worker-group');
    const syncEl       = document.getElementById('settings-sync-controls');
    const upgradeEl    = document.getElementById('settings-upgrade-google');

    function show(el) { if(el) el.style.display = ''; }
    function hide(el) { if(el) el.style.display = 'none'; }

    if(isGuest()) {
      if(badgeEl) { badgeEl.textContent = 'Guest'; badgeEl.className = 'auth-badge auth-badge-guest'; }
      show(guestEl); hide(tokenEl); hide(googleInfoEl);
      hide(workerEl); hide(syncEl); hide(upgradeEl);

    } else if(isGoogleAccount()) {
      if(badgeEl) { badgeEl.textContent = 'Google Account'; badgeEl.className = 'auth-badge auth-badge-google'; }
      hide(guestEl); hide(tokenEl); hide(upgradeEl);
      show(googleInfoEl); show(workerEl); show(syncEl);
      if(googleInfoEl) {
        const g = d.linkedGoogle;
        googleInfoEl.innerHTML = g
          ? `<div class="auth-google-info">
               ${g.picture ? `<img src="${g.picture}" class="auth-google-avatar" alt="">` : ''}
               <div>
                 <div style="font-size:.85rem;font-weight:500;">${_esc(g.name||'')}</div>
                 <div style="font-size:.78rem;opacity:.6;">${_esc(g.email||'')}</div>
               </div>
             </div>`
          : '';
      }

    } else {
      // Token account
      if(badgeEl) { badgeEl.textContent = 'Token'; badgeEl.className = 'auth-badge auth-badge-token'; }
      hide(guestEl); show(tokenEl); hide(googleInfoEl);
      show(workerEl); show(syncEl);
      if(upgradeEl) upgradeEl.style.display = isGoogleAuthAvailable() ? '' : 'none';
      // Populate token display
      const tokenDisplay = document.getElementById('settings-token-display');
      if(tokenDisplay) tokenDisplay.textContent = d.userToken || '—';
    }
  }

  // ── HTML escape helper ──────────────────────────────────────────
  // Internal only — used when rendering profile data into innerHTML.
  function _esc(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ══════════════════════════════════════════════════════════════════
  // ACCOUNT SETUP WIZARD
  // ══════════════════════════════════════════════════════════════════
  //
  // Screen flow:
  //   S1  Welcome
  //        ├─ "Yes, load existing" → S2A (choose token or Google)
  //        ├─ "No, start fresh"    → S2B (firstName/lastName/username + worker + auth)
  //        └─ "Try as guest"       → SG  (optional firstName/lastName/username)
  //
  //   S2A  Load existing
  //        ├─ "Token"  → S3B (worker URL + token entry)
  //        └─ "Google" → S3A (worker URL → unlock Google button)
  //
  //   S2B  Start fresh
  //        ├─ "Use Token"   → creates token account, enters app
  //        └─ "Link Google" → tests worker → SFG (Google button)
  //
  // All screens share the same modal: modal-account-setup.
  // The title and body are swapped by setupScreen().
  // ══════════════════════════════════════════════════════════════════

  // setupScreen() — sets the modal title and body, then opens the modal.
  // Every wizard screen calls this. Adding openModal here means screens
  // work whether the modal is already open (wizard navigation) or closed
  // (called directly from Settings).
  function setupScreen(title, html) {
    document.getElementById('account-setup-title').textContent = title;
    document.getElementById('account-setup-body').innerHTML = html;
    C.openModal('modal-account-setup');
  }

  // ── S1: Welcome ─────────────────────────────────────────────────
  // Entry point for new devices or when switching accounts.
  // HOST APP INTERFACE: none at this level (child screens call into config)
  function showAccountSetup() {
    setupScreen(`Welcome to ${appName()}`, `
      <p class="f13 lh muted" style="margin-bottom:1.5rem;">
        Do you already have a ${appName()} account on another device?
      </p>
      <div class="form-actions" style="flex-direction:column;gap:.65rem;">
        <button class="btn btn-primary w100" id="auth-btn-has-account" style="justify-content:center;">
          Yes — load my existing account
        </button>
        <button class="btn btn-ghost w100" id="auth-btn-new-account" style="justify-content:center;">
          No — start fresh
        </button>
        <div class="auth-divider"><span>or</span></div>
        <button class="btn btn-ghost w100" id="auth-btn-guest" style="justify-content:center;opacity:.7;">
          Try as a guest
        </button>
      </div>
    `);
    C.openModal('modal-account-setup');
    document.getElementById('auth-btn-has-account').addEventListener('click', showSetupLoadChoice);
    document.getElementById('auth-btn-new-account').addEventListener('click', showSetupFresh);
    document.getElementById('auth-btn-guest').addEventListener('click', showSetupGuest);
  }

  // ── SG: Guest intro ─────────────────────────────────────────────
  // Optional firstName, lastName, username before entering as guest.
  // All fields are optional — "skip and jump straight in" is valid.
  // HOST APP INTERFACE: calls getData(), setData(), onGuestReady()
  function showSetupGuest() {
    setupScreen('Just Exploring?', `
      <p class="f13 lh muted" style="margin-bottom:1rem;">
        Tell us a little about yourself — or skip and jump straight in.
        You can always fill this in later from Settings.
      </p>
      <div class="form-group">
        <label class="form-label">First Name <span class="muted" style="font-size:.78rem;">(optional)</span></label>
        <input class="input" id="auth-guest-firstname" placeholder="First name…"/>
      </div>
      <div class="form-group">
        <label class="form-label">Last Name <span class="muted" style="font-size:.78rem;">(optional)</span></label>
        <input class="input" id="auth-guest-lastname" placeholder="Last name…"/>
      </div>
      <div class="form-group">
        <label class="form-label">Username <span class="muted" style="font-size:.78rem;">(optional)</span></label>
        <input class="input" id="auth-guest-username" placeholder="Choose a username…"/>
      </div>
      <div class="form-actions" style="flex-direction:column;gap:.65rem;margin-top:.5rem;">
        <button class="btn btn-primary w100" id="auth-btn-guest-continue" style="justify-content:center;">
          Continue as Guest
        </button>
        <button class="btn btn-ghost btn-sm" id="auth-btn-back" style="justify-content:center;">← Back</button>
      </div>
    `);
    document.getElementById('auth-btn-back').addEventListener('click', showAccountSetup);
    document.getElementById('auth-btn-guest-continue').addEventListener('click', () => {
      const firstName = document.getElementById('auth-guest-firstname').value.trim();
      const lastName  = document.getElementById('auth-guest-lastname').value.trim();
      const username  = document.getElementById('auth-guest-username').value.trim();
      const d = getData();
      d.authMethod = 'guest';
      if(firstName) d.firstName = firstName;
      if(lastName)  d.lastName  = lastName;
      if(username)  d.username  = username;
      C.setData(d);
      C.closeModal('modal-account-setup');
      C.onGuestReady(d);
      C.toast(`Exploring as guest — create an account anytime from Settings ${appEmoji()}`);
    });
  }

  // ── S2A: Load existing — choose auth method ──────────────────────
  function showSetupLoadChoice() {
    setupScreen('Load Existing Account', `
      <p class="f13 lh muted" style="margin-bottom:1.25rem;">
        How is your account secured?
      </p>
      <div class="form-actions" style="flex-direction:column;gap:.65rem;">
        <button class="btn btn-primary w100" id="auth-btn-load-token" style="justify-content:center;">
          Continue with token
        </button>
        <button class="btn btn-ghost w100" id="auth-btn-load-google" style="justify-content:center;">
          Sign in with Google
        </button>
        <div class="auth-divider" style="margin:.1rem 0;"></div>
        <button class="btn btn-ghost btn-sm" id="auth-btn-back" style="justify-content:center;">← Back</button>
      </div>
    `);
    document.getElementById('auth-btn-back').addEventListener('click', showAccountSetup);
    document.getElementById('auth-btn-load-token').addEventListener('click', showSetupLoadToken);
    document.getElementById('auth-btn-load-google').addEventListener('click', showSetupLoadGoogle);
  }

  // ── S3A: Load via Google — worker URL first, then Google button ──
  // Google button is greyed out and pointer-events disabled until the
  // worker URL is confirmed reachable. This prevents the "no worker URL"
  // error that occurs when handleGoogleCredential fires without a base URL.
  // HOST APP INTERFACE: calls getData(), startSyncPing()
  function showSetupLoadGoogle() {
    setupScreen('Sign in with Google', `
      <p class="f13 lh muted" style="margin-bottom:1rem;">
        Enter your Worker URL to connect, then sign in with Google.
      </p>
      <div class="form-group">
        <label class="form-label">Worker URL</label>
        <div class="row gap-8">
          <input class="input" id="auth-setup-worker-url"
                 placeholder="https://your-worker.workers.dev" style="flex:1;"/>
          <button class="btn btn-outline btn-sm" id="auth-btn-test-worker"
                  style="white-space:nowrap;">Test</button>
        </div>
        <div id="auth-setup-status" style="min-height:1.3rem;font-size:.82rem;margin-top:.35rem;"></div>
      </div>
      <div id="auth-google-btn-container"
           style="width:100%;min-height:44px;transition:opacity .25s;">
      </div>
      <div class="row gap-8 mt-8" style="justify-content:flex-start;">
        <button class="btn btn-ghost btn-sm" id="auth-btn-back">← Back</button>
      </div>
    `);

    document.getElementById('auth-btn-back').addEventListener('click', showSetupLoadChoice);

    const workerInput = document.getElementById('auth-setup-worker-url');
    const statusEl    = document.getElementById('auth-setup-status');
    const googleCtr   = document.getElementById('auth-google-btn-container');

    async function unlockGoogle() {
      const url = workerInput.value.trim();
      if(!url) { statusEl.style.color='var(--red,#c07070)'; statusEl.textContent='Enter a Worker URL first.'; return; }
      statusEl.style.color = 'var(--gold2, #b8985a)';
      statusEl.textContent = 'Testing connection…';
      const ok = await testWorkerUrl(url);
      if(!ok) {
        statusEl.style.color = 'var(--red, #c07070)';
        statusEl.textContent = 'Could not reach that URL — check it and try again.';
        return;
      }

      // Worker confirmed — save URL and fetch the Google client ID from it
      const d = getData(); d.workerUrl = url.replace(/\/+$/, ''); C.setData(d);
      statusEl.style.color = 'var(--gold2, #b8985a)';
      statusEl.textContent = 'Fetching auth config…';

      try {
        const res  = await fetch(`${d.workerUrl}/auth/config`);
        const cfg  = await res.json();
        if(cfg.googleClientId) C.googleClientId = cfg.googleClientId;
      } catch { /* use existing clientId if any */ }

      if(!C.googleClientId) {
        statusEl.style.color = 'var(--red, #c07070)';
        statusEl.textContent = 'Worker did not return a Google client ID — check your worker config.';
        return;
      }

      statusEl.style.color = 'var(--green, #6daa8f)';
      statusEl.textContent = 'Connected ✓ — sign in with Google below.';

      // Now render the Google button with a valid client ID
      googleCtr.innerHTML = '';
      signInWithGoogle(googleCtr).then(result => {
        if(result?.ok) {
          C.closeModal('modal-account-setup');
          C.toast(result.isNewAccount
            ? `Welcome to ${appName()} ${appEmoji()}`
            : 'Account loaded ✓');
          C.startSyncPing();
        } else if(result === null) {
          statusEl.style.color = 'var(--red, #c07070)';
          statusEl.textContent = 'Sign-in cancelled — try again.';
        }
      });
    }

    document.getElementById('auth-btn-test-worker').addEventListener('click', unlockGoogle);
    workerInput.addEventListener('keydown', e => { if(e.key==='Enter') unlockGoogle(); });
  }

  // ── S3B: Load via token ──────────────────────────────────────────
  // If workerUrl is already set (came from S2B), skip asking for it again.
  // HOST APP INTERFACE: calls getData(), setData(), mergeData(), onSignedIn(), startSyncPing()
  function showSetupLoadToken() {
    const existingWorker = getData()?.workerUrl || '';

    setupScreen('Load with Token', `
      <p class="f13 lh muted" style="margin-bottom:1rem;">
        Paste the sync token from your other device.
      </p>
      ${!existingWorker ? `
      <div class="form-group">
        <label class="form-label">Worker URL</label>
        <input class="input" id="auth-setup-worker-url"
               placeholder="https://your-worker.workers.dev"/>
      </div>` : `
      <div class="form-group">
        <label class="form-label">Worker URL</label>
        <div class="input" style="color:var(--muted);background:var(--cream-dark);cursor:default;">
          ${_esc(existingWorker)}
        </div>
      </div>`}
      <div class="form-group">
        <label class="form-label">Your Token</label>
        <input class="input input-mono" id="auth-setup-token"
               placeholder="Paste your token here…"/>
      </div>
      <div id="auth-setup-status"
           style="min-height:1.4rem;font-size:.82rem;color:var(--red,#c07070);margin-bottom:.5rem;">
      </div>
      <div class="row gap-8" style="justify-content:space-between;">
        <button class="btn btn-ghost" id="auth-btn-back">← Back</button>
        <button class="btn btn-primary" id="auth-btn-load" ${existingWorker ? '' : 'disabled'}>Load Account</button>
      </div>
    `);

    document.getElementById('auth-btn-back').addEventListener('click', showSetupLoadChoice);

    const workerInput = document.getElementById('auth-setup-worker-url'); // null if pre-filled
    const tokenInput  = document.getElementById('auth-setup-token');
    const loadBtn     = document.getElementById('auth-btn-load');
    const statusEl    = document.getElementById('auth-setup-status');

    // Enable load button when required fields have content
    function checkFields() {
      const workerOk = existingWorker || (workerInput?.value.trim());
      loadBtn.disabled = !(workerOk && tokenInput.value.trim());
    }
    workerInput?.addEventListener('input', checkFields);
    tokenInput.addEventListener('input', checkFields);

    loadBtn.addEventListener('click', async () => {
      const workerUrl = existingWorker || workerInput?.value.trim() || '';
      const token     = tokenInput.value.trim();
      loadBtn.disabled = true;
      statusEl.style.color = 'var(--gold2, #b8985a)';
      statusEl.textContent = 'Looking up account…';

      const d = getData();
      d.workerUrl = workerUrl;
      C.setData(d);

      let remote = null;
      try {
        const base    = workerUrl.replace(/\/+$/,'');
        const hmacHdrs = await _signRequest('GET', token, '').catch(() => ({}));
        const res = await fetch(`${base}/storage/${encodeURIComponent(token)}/profile`, {
          headers: hmacHdrs,
        });
        if(res.ok) { const j = await res.json(); remote = j.value ?? j; }
      } catch {}

      if(!remote) {
        statusEl.style.color = 'var(--red, #c07070)';
        statusEl.textContent = 'No account found. Check both fields and try again.';
        d.workerUrl = '';
        C.setData(d);
        loadBtn.disabled = false;
        return;
      }

      const merged = C.mergeData(remote);
      merged.workerUrl = workerUrl;
      C.onSignedIn(merged, false);
      C.closeModal('modal-account-setup');
      C.startSyncPing();
      C.toast('Account loaded ✓');
    });
  }

  // ── S2B: Start fresh (also used for guest → account conversion) ──
  // Name fields optional, worker URL required.
  // Auth method chosen via buttons at bottom.
  // HOST APP INTERFACE: calls getData(), setData(), onSignedIn(),
  //                     pushToWorker(), startSyncPing()
  function showSetupFresh() {
    const d             = getData();
    const existingFirst = d?.firstName || '';
    const existingLast  = d?.lastName  || '';
    const existingUser  = d?.username  || '';
    const title = isGuest() ? 'Create Your Account' : 'Start Fresh';
    const intro = isGuest()
      ? `Set up your account to save your data across devices. Everything you've done as a guest comes with you.`
      : 'Tell us a little about yourself to get started.';

    const googleOption = isGoogleAuthAvailable()
      ? `<button class="btn btn-ghost w100" id="auth-btn-fresh-google" style="justify-content:center;">
           Link Google Account
         </button>`
      : '';

    setupScreen(title, `
      <p class="f13 lh muted" style="margin-bottom:1rem;">${intro}</p>
      <div class="form-group">
        <label class="form-label">First Name <span class="muted" style="font-size:.78rem;">(optional)</span></label>
        <input class="input" id="auth-fresh-firstname"
               placeholder="First name…"
               value="${_esc(existingFirst)}"/>
      </div>
      <div class="form-group">
        <label class="form-label">Last Name <span class="muted" style="font-size:.78rem;">(optional)</span></label>
        <input class="input" id="auth-fresh-lastname"
               placeholder="Last name…"
               value="${_esc(existingLast)}"/>
      </div>
      <div class="form-group">
        <label class="form-label">Username <span class="muted" style="font-size:.78rem;">(optional)</span></label>
        <input class="input" id="auth-fresh-username"
               placeholder="Choose a username…"
               value="${_esc(existingUser)}"/>
      </div>
      <div class="form-group">
        <label class="form-label">Worker URL</label>
        <input class="input" id="auth-fresh-worker"
               placeholder="https://your-worker.workers.dev"/>
        <div class="form-hint">Required for cross-device sync.</div>
      </div>
      <div id="auth-fresh-status"
           style="min-height:1.3rem;font-size:.82rem;color:var(--red,#c07070);margin-bottom:.5rem;">
      </div>
      <div class="form-actions" style="flex-direction:column;gap:.65rem;">
        <button class="btn btn-primary w100" id="auth-btn-fresh-token" style="justify-content:center;">
          Use Token
        </button>
        ${googleOption}
        <div class="auth-divider" style="margin:.1rem 0;"></div>
        <button class="btn btn-ghost btn-sm" id="auth-btn-back" style="justify-content:center;">← Back</button>
      </div>
    `);

    // Back: guests close modal, new users go to S1
    document.getElementById('auth-btn-back').addEventListener('click', () => {
      if(isGuest()) { C.closeModal('modal-account-setup'); } else { showAccountSetup(); }
    });

    const firstInput  = document.getElementById('auth-fresh-firstname');
    const lastInput   = document.getElementById('auth-fresh-lastname');
    const userInput   = document.getElementById('auth-fresh-username');
    const workerInput = document.getElementById('auth-fresh-worker');
    const statusEl    = document.getElementById('auth-fresh-status');

    function validate() {
      if(!workerInput.value.trim()) { statusEl.textContent = 'Please enter your Worker URL.'; return false; }
      statusEl.textContent = '';
      return true;
    }

    // ── Token path ─────────────────────────────────────────────
    document.getElementById('auth-btn-fresh-token').addEventListener('click', async () => {
      if(!validate()) return;
      const firstName = firstInput.value.trim();
      const lastName  = lastInput.value.trim();
      const username  = userInput.value.trim();
      const worker    = workerInput.value.trim();
      statusEl.style.color = 'var(--gold2, #b8985a)';
      statusEl.textContent = 'Creating account…';

      const d = getData();
      if(firstName) d.firstName = firstName;
      if(lastName)  d.lastName  = lastName;
      if(username)  d.username  = username;
      d.workerUrl  = worker.replace(/\/+$/, '');
      d.authMethod = 'token';
      C.setData(d);

      const ok = await C.pushToWorker();
      if(!ok) {
        statusEl.style.color = 'var(--red, #c07070)';
        statusEl.textContent = 'Could not reach Worker URL — check it and try again.';
        d.workerUrl = '';
        C.setData(d);
        return;
      }

      C.closeModal('modal-account-setup');
      C.startSyncPing();
      C.onSignedIn(d, true);
      C.toast(`Welcome${firstName ? ', ' + firstName : ''} ${appEmoji()}`);
    });

    // ── Google path ─────────────────────────────────────────────
    if(isGoogleAuthAvailable()) {
      document.getElementById('auth-btn-fresh-google')?.addEventListener('click', async () => {
        if(!validate()) return;
        const firstName = firstInput.value.trim();
        const lastName  = lastInput.value.trim();
        const username  = userInput.value.trim();
        const worker    = workerInput.value.trim();
        statusEl.style.color = 'var(--gold2, #b8985a)';
        statusEl.textContent = 'Testing connection…';

        const d = getData();
        if(firstName) d.firstName = firstName;
        if(lastName)  d.lastName  = lastName;
        if(username)  d.username  = username;
        d.workerUrl  = worker.replace(/\/+$/, '');
        C.setData(d);

        const ok = await testWorkerUrl(d.workerUrl);
        if(!ok) {
          statusEl.style.color = 'var(--red, #c07070)';
          statusEl.textContent = 'Could not reach Worker URL — check it and try again.';
          d.workerUrl = '';
          C.setData(d);
          return;
        }

        statusEl.textContent = 'Connected — opening Google sign-in…';
        showSetupFreshGoogle(firstName, lastName, username, worker);
      });
    }
  }

  // ── SFG: Fresh Google sign-in step ──────────────────────────────
  // Final step for "start fresh with Google". Data already set on D
  // before this screen is shown. Google button renders immediately.
  // HOST APP INTERFACE: calls getData(), setData(), startSyncPing()
  function showSetupFreshGoogle(firstName, lastName, username, workerUrl) {
    setupScreen('Link Google Account', `
      <p class="f13 lh muted" style="margin-bottom:1rem;">
        Sign in with Google to secure your new account.
      </p>
      <div id="auth-fresh-google-container" style="width:100%;min-height:44px;"></div>
      <div id="auth-fresh-status" style="min-height:1.3rem;font-size:.82rem;margin-top:.5rem;"></div>
      <div class="row gap-8 mt-8" style="justify-content:flex-start;">
        <button class="btn btn-ghost btn-sm" id="auth-btn-back">← Back</button>
      </div>
    `);

    document.getElementById('auth-btn-back').addEventListener('click', showSetupFresh);

    const container = document.getElementById('auth-fresh-google-container');
    const statusEl  = document.getElementById('auth-fresh-status');

    const d = getData();
    if(firstName) d.firstName = firstName;
    if(lastName)  d.lastName  = lastName;
    if(username)  d.username  = username;
    d.workerUrl  = workerUrl.replace(/\/+$/, '');
    C.setData(d);

    signInWithGoogle(container).then(result => {
      if(result?.ok) {
        C.closeModal('modal-account-setup');
        C.toast(`Welcome${firstName ? ', ' + firstName : ''} ${appEmoji()}`);
        C.startSyncPing();
      } else {
        statusEl.style.color = 'var(--red, #c07070)';
        statusEl.textContent = 'Sign-in cancelled — try again or go back.';
      }
    });
  }

  // ── Token → Google upgrade (called from Settings) ────────────────
  // One-way permanent migration. Worker URL pre-filled and pre-tested
  // if already configured. Token captured BEFORE signInWithGoogle runs
  // because handleGoogleCredential overwrites D.userToken with the
  // Google KV key — reading it after would give the wrong value.
  // HOST APP INTERFACE: calls getData(), setData(), workerBase(), startSyncPing()
  function showGoogleUpgradeFlow() {
    const d = getData();
    setupScreen('Upgrade to Google Sign-In', `
      <p class="f13 lh muted" style="margin-bottom:1rem;">
        Upgrading links your account to Google permanently.
        Your token will stop working after this — it's a one-way change.
      </p>
      <div class="form-group">
        <label class="form-label">Worker URL</label>
        <div class="row gap-8">
          <input class="input" id="auth-upgrade-worker" value="${_esc(d.workerUrl||'')}" style="flex:1;"/>
          <button class="btn btn-outline btn-sm" id="auth-btn-test-worker" style="white-space:nowrap;">Test</button>
        </div>
        <div id="auth-upgrade-status" style="min-height:1.3rem;font-size:.82rem;margin-top:.35rem;"></div>
      </div>
      <div id="auth-upgrade-google-container"
           style="width:100%;min-height:44px;opacity:.35;pointer-events:none;transition:opacity .25s;">
      </div>
      <div class="row gap-8 mt-8" style="justify-content:flex-start;">
        <button class="btn btn-ghost btn-sm" id="auth-btn-cancel">Cancel</button>
      </div>
    `);
    C.openModal('modal-account-setup');

    document.getElementById('auth-btn-cancel').addEventListener('click', () => {
      C.closeModal('modal-account-setup');
    });

    const workerInput = document.getElementById('auth-upgrade-worker');
    const statusEl    = document.getElementById('auth-upgrade-status');
    const googleCtr   = document.getElementById('auth-upgrade-google-container');

    // Capture oldToken before any Google auth runs — it gets overwritten later.
    const oldToken = getData().userToken;

    // Use a raw GIS credential capture rather than signInWithGoogle() to avoid
    // handleGoogleCredential() creating a new Google-keyed account (or pushing
    // authMethod:google to the worker) before the /auth/migrate call completes.
    // That race caused a 409 "account already exists" error on the migrate endpoint.
    const idTokenPromise = new Promise((resolve) => {
      google.accounts.id.initialize({
        client_id:   C.googleClientId,
        auto_select: false,
        callback: (response) => {
          google.accounts.id.cancel();
          resolve(response?.credential || null);
        },
      });
      google.accounts.id.renderButton(googleCtr, {
        theme: 'filled_black', size: 'large',
        width: googleCtr.offsetWidth || 280,
        text: 'continue_with', locale: 'en', ux_mode: 'popup',
      });
    });

    idTokenPromise.then(async (idToken) => {
      if (!idToken) {
        statusEl.style.color = 'var(--red, #c07070)';
        statusEl.textContent = 'Sign-in cancelled — try again.';
        googleCtr.style.opacity = '1';
        googleCtr.style.pointerEvents = 'auto';
        return;
      }

      const base        = workerBase();
      const migrateBody = JSON.stringify({ idToken, oldToken });
      // Sign with oldToken via HMAC directly — not _authHeaders which checks
      // account type and could send Bearer if authMethod has changed.
      const hmacHdrs    = await _signRequest('POST', oldToken, migrateBody).catch(() => ({}));
      statusEl.style.color = 'var(--gold2, #b8985a)';
      statusEl.textContent = 'Migrating account…';

      try {
        const res  = await fetch(`${base}/auth/migrate`, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json', ...hmacHdrs },
          body:    migrateBody,
        });
        const data = await res.json();
        if(!res.ok || !data.ok) throw new Error(data.error || 'Migration failed');

        // Migration succeeded — now update local state and store the idToken
        store.set(C.storageAuthKey, idToken);
        const d = getData();
        d.authMethod   = 'google';
        d.linkedGoogle = data.profile;
        d.userToken    = data.kvKey;
        store.set(C.storageDismissKey, true);
        C.setData(d);

        C.closeModal('modal-account-setup');
        C.toast('Account upgraded to Google sign-in ✓');
        C.onSignedIn(d, false);
      } catch(err) {
        statusEl.style.color = 'var(--red, #c07070)';
        statusEl.textContent = `Migration failed: ${err.message}`;
      }
    });

    async function unlockUpgrade() {
      const url = workerInput.value.trim();
      if(!url) { statusEl.style.color='var(--red,#c07070)'; statusEl.textContent='Enter a Worker URL first.'; return; }
      statusEl.style.color = 'var(--gold2, #b8985a)';
      statusEl.textContent = 'Testing connection…';
      const ok = await testWorkerUrl(url);
      if(ok) {
        const d = getData(); d.workerUrl = url.replace(/\/+$/, ''); C.setData(d);
        statusEl.style.color = 'var(--green, #6daa8f)';
        statusEl.textContent = 'Connected ✓ — sign in with Google below to complete upgrade.';
        googleCtr.style.opacity = '1';
        googleCtr.style.pointerEvents = 'auto';
      } else {
        statusEl.style.color = 'var(--red, #c07070)';
        statusEl.textContent = 'Could not reach that URL — check it and try again.';
      }
    }

    document.getElementById('auth-btn-test-worker').addEventListener('click', unlockUpgrade);
    // Pre-test if worker URL already set — no click needed if already confirmed
    if(d.workerUrl) unlockUpgrade();
  }

  // ── Guest switch account ─────────────────────────────────────────
  // Shown when a guest clicks "Switch Account" in Settings.
  // Confirms before clearing local data, then reloads to the wizard.
  // For guests there are no server-side credentials — clearing storage
  // is the complete sign-out.
  //
  // storagePrefix: the host app's localStorage key prefix (e.g. 'rev_').
  // All keys matching the prefix are removed on confirm.
  // HOST APP INTERFACE: calls C.closeModal(), C.storageKey (to derive prefix)
  function showGuestSwitchConfirm() {
    setupScreen('Switch Account', `
      <p class="f13 lh muted" style="margin-bottom:1rem;">
        Switching accounts will clear all guest data on this device.
        This cannot be undone — any entries or progress you've made as a
        guest will be lost unless you create an account first.
      </p>
      <div class="form-actions" style="flex-direction:column;gap:.65rem;">
        <button class="btn btn-primary w100" id="auth-btn-guest-switch-confirm"
                style="justify-content:center;">
          Clear data and switch
        </button>
        <button class="btn btn-ghost w100" id="auth-btn-guest-switch-cancel"
                style="justify-content:center;">
          Cancel
        </button>
      </div>
    `);

    document.getElementById('auth-btn-guest-switch-cancel').addEventListener('click', () => {
      C.closeModal('modal-account-setup');
    });

    document.getElementById('auth-btn-guest-switch-confirm').addEventListener('click', () => {
      // Derive the storage prefix from the storageKey config value.
      // e.g. storageKey 'rev_appdata' → prefix 'rev_'
      // Falls back to clearing just the known auth module keys if no
      // underscore separator is found.
      const key    = C.storageKey || '';
      const sep    = key.lastIndexOf('_');
      const prefix = sep > 0 ? key.slice(0, sep + 1) : null;

      if(prefix) {
        Object.keys(localStorage)
          .filter(k => k.startsWith(prefix))
          .forEach(k => localStorage.removeItem(k));
      } else {
        // No prefix pattern — clear just the known module keys
        store.remove(C.storageKey);
        store.remove(C.storageAuthKey);
        store.remove(C.storageDismissKey);
      }
      location.reload();
    });
  }

  // ── Token upgrade prompt (legacy → secure) ───────────────────────
  // Shown once to users whose token was generated by Math.random().
  // Offers upgrade to a 128-bit cryptographic token. Secondary devices
  // auto-migrate via X-Token-Migrated header — no action needed there.
  // HOST APP INTERFACE: calls getData(), setData(), workerBase()
  function showTokenUpgradePrompt() {
    document.getElementById('account-setup-title').textContent = 'Security Upgrade Available';
    document.getElementById('account-setup-body').innerHTML = `
      <p class="f13 lh muted" style="margin-bottom:1rem;">
        Your account token was created with an older method. A more secure token
        is now available — upgrading takes about 10 seconds and your data stays intact.
      </p>
      <p class="f13 lh muted" style="margin-bottom:1.25rem;">
        Any other devices using this account will upgrade automatically the next
        time they sync — no action needed on your part.
      </p>
      <div id="auth-upgrade-status"
           style="min-height:1.4rem;font-size:.82rem;color:var(--red,#c07070);margin-bottom:.75rem;">
      </div>
      <div class="form-actions" style="flex-direction:column;gap:.65rem;">
        <button class="btn btn-primary w100" id="auth-btn-upgrade-token" style="justify-content:center;">
          Upgrade to secure token
        </button>
        <button class="btn btn-ghost w100" id="auth-btn-upgrade-dismiss" style="justify-content:center;">
          Keep my current token
        </button>
      </div>
    `;
    C.openModal('modal-account-setup');

    document.getElementById('auth-btn-upgrade-dismiss').addEventListener('click', () => {
      store.set(C.storageDismissKey, true);
      C.closeModal('modal-account-setup');
      C.toast('Token kept — you can upgrade later from Settings.');
    });

    document.getElementById('auth-btn-upgrade-token').addEventListener('click', async () => {
      const statusEl = document.getElementById('auth-upgrade-status');
      const btn      = document.getElementById('auth-btn-upgrade-token');
      btn.disabled   = true;
      btn.textContent = 'Upgrading…';

      const oldToken = getData().userToken;
      const newToken = generateToken();
      const base     = workerBase();

      if(base) {
        statusEl.style.color = 'var(--gold2, #b8985a)';
        statusEl.textContent = 'Copying data to new token on worker…';

        const d = getData();
        d.userToken = newToken;
        const payload    = { ...d, _legacyToken: oldToken };
        const bodyStr    = JSON.stringify(payload);
        const hmacHdrs   = await _signRequest('PUT', newToken, bodyStr).catch(() => ({}));

        let ok = false;
        try {
          const res = await fetch(`${base}/storage/${encodeURIComponent(newToken)}/profile`, {
            method:  'PUT',
            headers: { 'Content-Type': 'application/json', ...hmacHdrs },
            body:    bodyStr,
          });
          ok = res.ok;
        } catch { ok = false; }

        if(!ok) {
          d.userToken = oldToken;
          C.setData(d);
          btn.disabled = false;
          btn.textContent = 'Upgrade to secure token';
          statusEl.style.color = 'var(--red, #c07070)';
          statusEl.textContent = 'Worker sync failed — your old token is unchanged.';
          return;
        }
      }

      const d = getData();
      d.userToken = newToken;
      store.set(C.storageDismissKey, true);
      C.setData(d);

      // Show the new token so user can note it if they want
      document.getElementById('account-setup-title').textContent = 'Token Upgraded ✓';
      document.getElementById('account-setup-body').innerHTML = `
        <p class="f13 lh muted" style="margin-bottom:1rem;">
          Your account is now secured with a stronger token.
          Other devices will upgrade automatically on their next sync.
        </p>
        <p class="f13 lh muted" style="margin-bottom:.5rem;">Your new token:</p>
        <div style="display:flex;gap:.5rem;align-items:center;margin-bottom:1.25rem;">
          <code class="input input-mono"
                style="flex:1;font-size:.78rem;padding:.5rem .65rem;user-select:all;cursor:text;">
            ${newToken}
          </code>
          <button class="btn btn-outline btn-sm" id="auth-btn-copy-token">Copy</button>
        </div>
        <div class="form-actions">
          <button class="btn btn-primary w100" id="auth-btn-upgrade-done"
                  style="justify-content:center;">Done</button>
        </div>
      `;

      document.getElementById('auth-btn-copy-token').addEventListener('click', () => {
        navigator.clipboard.writeText(newToken).then(() => {
          document.getElementById('auth-btn-copy-token').textContent = 'Copied!';
          setTimeout(() => {
            const el = document.getElementById('auth-btn-copy-token');
            if(el) el.textContent = 'Copy';
          }, 2000);
        }).catch(() => { C.toast('Select the token above and copy manually.'); });
      });

      document.getElementById('auth-btn-upgrade-done').addEventListener('click', () => {
        C.closeModal('modal-account-setup');
        C.toast('Token upgraded ✓');
      });
    });
  }

  // ── Public API ───────────────────────────────────────────────────
  // This is the only surface area exposed to the host app.
  // Everything else is internal to the IIFE.
  return {

    // init(config) — MUST be called before any other Auth method.
    // See the INTEGRATION CHECKLIST at the top of this file for the
    // full list of required and optional config keys.
    init(config) {
      C = config;
    },

    // Account type checks — safe to call at any time after init()
    isGuest,
    isTokenAccount,
    isGoogleAccount,
    isGoogleAuthAvailable,

    // Wizard entry points
    showAccountSetup,       // S1 welcome screen
    showSetupFresh,         // S2B start fresh (also guest → account conversion)
    showSetupLoadToken,     // S3B enter existing token (call from Settings)
    showGoogleUpgradeFlow,  // token → Google upgrade (call from Settings)
    showGoogleReauth,       // re-auth after session expiry (called automatically by bootCheck)
    showGuestSwitchConfirm, // guest switch/reset (call from Settings)
    showTokenUpgradePrompt, // legacy token upgrade prompt (call from boot)

    // Session management
    signInWithGoogle,       // render GIS button and sign in
    signOutGoogle,          // revoke session locally
    verifyGoogleSession,    // call at boot for Google accounts

    // Boot helpers
    bootCheck,              // call after worker pull in DOMContentLoaded
    handlePullMigration,    // call from pullFromWorker on X-Token-Migrated header

    // Settings modal
    renderSettingsSection,  // call from openSettingsModal

    // Token utilities — host app may need these
    generateToken,          // 128-bit base64url token
    isLegacyToken,          // detect old Math.random() tokens
    _authHeaders,           // build auth headers for worker requests (HMAC or Bearer)
  };

})();
