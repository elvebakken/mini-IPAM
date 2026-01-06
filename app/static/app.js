const state = {
    me: null,
    vlans: [],
    currentVlan: null,
    filterText: "",
    filterType: "all",
    dark: true,
    loading: new Set(), // Track active loading operations
    viewMode: "table" // "table" or "card" for mobile responsiveness
  };
  
  function el(html) {
    const t = document.createElement("template");
    t.innerHTML = html.trim();
    return t.content.firstChild;
  }

  // Loading state management
  function setLoading(key, isLoading) {
    if (isLoading) {
      state.loading.add(key);
    } else {
      state.loading.delete(key);
    }
    // Trigger custom event for components that need to react to loading changes
    window.dispatchEvent(new CustomEvent('loadingchange', { detail: { key, isLoading } }));
  }

  function isLoading(key) {
    return state.loading.has(key);
  }

  // Spinner component
  function spinner(size = "w-4 h-4") {
    return el(`
      <svg class="${size} animate-spin text-zinc-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
      </svg>
    `);
  }

  // Skeleton loader for cards
  function skeletonCard() {
    return el(`
      <div class="bg-zinc-900 border border-zinc-800 rounded-2xl p-4 animate-pulse">
        <div class="flex items-start justify-between gap-3">
          <div class="flex-1">
            <div class="h-5 bg-zinc-800 rounded w-32 mb-2"></div>
            <div class="h-4 bg-zinc-800 rounded w-48"></div>
          </div>
          <div class="h-4 bg-zinc-800 rounded w-12"></div>
        </div>
        <div class="mt-3 h-2 bg-zinc-800 rounded-full"></div>
        <div class="mt-3 flex gap-3">
          <div class="h-4 bg-zinc-800 rounded w-16"></div>
          <div class="h-4 bg-zinc-800 rounded w-20"></div>
        </div>
      </div>
    `);
  }

  // Skeleton loader for table rows
  function skeletonTableRow() {
    return el(`
      <tr class="border-b border-zinc-900">
        <td class="p-3"><div class="w-8 h-8 bg-zinc-800 rounded-md animate-pulse"></div></td>
        <td class="p-3"><div class="h-4 bg-zinc-800 rounded w-24 animate-pulse"></div></td>
        <td class="p-3"><div class="h-4 bg-zinc-800 rounded w-32 animate-pulse"></div></td>
        <td class="p-3"><div class="h-5 bg-zinc-800 rounded-full w-16 animate-pulse"></div></td>
        <td class="p-3"><div class="h-5 bg-zinc-800 rounded-full w-20 animate-pulse"></div></td>
        <td class="p-3"><div class="h-4 bg-zinc-800 rounded w-40 animate-pulse"></div></td>
        <td class="p-3 text-right">
          <div class="flex gap-2 justify-end">
            <div class="w-6 h-6 bg-zinc-800 rounded animate-pulse"></div>
            <div class="w-6 h-6 bg-zinc-800 rounded animate-pulse"></div>
          </div>
        </td>
      </tr>
    `);
  }

  // Helper to set button loading state
  function setButtonLoading(button, isLoading, originalText = null) {
    if (!button) return;
    
    if (isLoading) {
      button.dataset.originalText = originalText || button.textContent.trim();
      button.disabled = true;
      button.classList.add("opacity-50", "cursor-not-allowed");
      
      // Add spinner if not already present
      if (!button.querySelector(".spinner")) {
        const sp = spinner("w-4 h-4");
        sp.classList.add("spinner", "inline-block", "mr-2");
        button.insertBefore(sp, button.firstChild);
      }
    } else {
      button.disabled = false;
      button.classList.remove("opacity-50", "cursor-not-allowed");
      
      // Remove spinner
      const sp = button.querySelector(".spinner");
      if (sp) sp.remove();
      
      // Restore original text if available
      if (button.dataset.originalText) {
        button.textContent = button.dataset.originalText;
        delete button.dataset.originalText;
      }
    }
  }
  
  function getCsrfToken() {
    // Read CSRF token from cookie
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrf_token') {
        return value;
      }
    }
    return null;
  }

  async function api(path, { method="GET", body=null, headers={}, loadingKey=null } = {}) {
    const loadingId = loadingKey || path;
    
    try {
      setLoading(loadingId, true);
      
      const opts = { method, headers: { ...headers } };
      
      // Add CSRF token header for state-changing requests
      if (method !== "GET" && method !== "HEAD") {
        const csrfToken = getCsrfToken();
        if (csrfToken) {
          opts.headers["X-CSRF-Token"] = csrfToken;
        }
      }
      
      if (body && !(body instanceof FormData)) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
      } else if (body instanceof FormData) {
        opts.body = body;
      }
      const res = await fetch(path, opts);
      const text = await res.text();
      let json = null;
      try { json = text ? JSON.parse(text) : null; } catch {}
      if (!res.ok) {
        const msg = json?.detail || json?.message || text || `HTTP ${res.status}`;
        throw new Error(msg);
      }
      return json;
    } finally {
      setLoading(loadingId, false);
    }
  }
  
  // Enhanced Toast Notification System
  const toastState = {
    container: null,
    queue: [],
    maxVisible: 5,
    defaultDuration: 3000
  };

  function initToastContainer() {
    if (!toastState.container) {
      toastState.container = el(`
        <div class="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none" style="max-width: 400px;"></div>
      `);
      document.body.appendChild(toastState.container);
    }
    return toastState.container;
  }

  function getToastTypeStyles(type) {
    const styles = {
      success: {
        bg: "bg-green-600",
        border: "border-green-500",
        icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
        </svg>`
      },
      error: {
        bg: "bg-red-600",
        border: "border-red-500",
        icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
        </svg>`
      },
      warning: {
        bg: "bg-yellow-600",
        border: "border-yellow-500",
        icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
        </svg>`
      },
      info: {
        bg: "bg-blue-600",
        border: "border-blue-500",
        icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
        </svg>`
      },
      default: {
        bg: "bg-zinc-800",
        border: "border-zinc-700",
        icon: ""
      }
    };
    return styles[type] || styles.default;
  }

  function createToastElement(id, message, type, duration, action) {
    const styles = getToastTypeStyles(type);
    const hasAction = action && action.label && action.onClick;
    
    const toastEl = el(`
      <div 
        data-toast-id="${id}"
        class="pointer-events-auto bg-zinc-900 border ${styles.border} rounded-lg shadow-xl overflow-hidden"
        style="animation: slideIn 0.3s ease-out forwards;"
      >
        <div class="flex items-start gap-3 p-3">
          ${styles.icon ? `<div class="${styles.bg} rounded-full p-1.5 flex-shrink-0 text-white">${styles.icon}</div>` : ''}
          <div class="flex-1 min-w-0">
            <div class="text-sm text-zinc-100">${escapeHtml(message)}</div>
            ${hasAction ? `
              <div class="mt-2 flex gap-2">
                <button 
                  data-action-btn
                  class="text-xs px-3 py-1.5 rounded-md font-medium transition ${styles.bg} text-white hover:opacity-90"
                >
                  ${escapeHtml(action.label)}
                </button>
              </div>
            ` : ''}
          </div>
          <button 
            data-close-btn
            class="flex-shrink-0 text-zinc-400 hover:text-zinc-200 transition p-1"
            aria-label="Close"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
          </button>
        </div>
        ${duration > 0 ? `
          <div class="h-1 bg-zinc-800">
            <div 
              data-progress-bar
              class="h-full ${styles.bg} transition-all linear"
              style="width: 100%;"
            ></div>
          </div>
        ` : ''}
      </div>
    `);

    // Add CSS animation if not already added
    if (!document.getElementById('toast-animations')) {
      const style = document.createElement('style');
      style.id = 'toast-animations';
      style.textContent = `
        @keyframes slideIn {
          from {
            transform: translateX(100%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }
        @keyframes slideOut {
          from {
            transform: translateX(0);
            opacity: 1;
          }
          to {
            transform: translateX(100%);
            opacity: 0;
          }
        }
      `;
      document.head.appendChild(style);
    }

    return toastEl;
  }

  function showToast(id, message, type, duration, action) {
    const container = initToastContainer();
    const toastEl = createToastElement(id, message, type, duration, action);
    container.appendChild(toastEl);

    // Handle action button
    const actionBtn = toastEl.querySelector('[data-action-btn]');
    if (actionBtn && action && action.onClick) {
      actionBtn.onclick = () => {
        action.onClick();
        dismissToast(id);
      };
    }

    // Handle close button
    const closeBtn = toastEl.querySelector('[data-close-btn]');
    if (closeBtn) {
      closeBtn.onclick = () => dismissToast(id);
    }

    // Auto-dismiss with progress
    if (duration > 0) {
      const progressBar = toastEl.querySelector('[data-progress-bar]');
      const startTime = Date.now();
      const updateProgress = () => {
        const elapsed = Date.now() - startTime;
        const remaining = Math.max(0, duration - elapsed);
        const progress = (remaining / duration) * 100;
        
        if (progressBar) {
          progressBar.style.width = `${progress}%`;
        }
        
        if (remaining > 0) {
          requestAnimationFrame(updateProgress);
        } else {
          dismissToast(id);
        }
      };
      requestAnimationFrame(updateProgress);
    }

    return id;
  }

  function dismissToast(id) {
    const container = toastState.container;
    if (!container) return;
    
    const toastEl = container.querySelector(`[data-toast-id="${id}"]`);
    if (!toastEl) return;

    // Animate out
    toastEl.style.animation = 'slideOut 0.3s ease-out forwards';
    
    setTimeout(() => {
      toastEl.remove();
      processToastQueue();
    }, 300);
  }

  function processToastQueue() {
    const container = toastState.container;
    if (!container) return;

    const visible = container.querySelectorAll('[data-toast-id]').length;
    const available = toastState.maxVisible - visible;

    while (toastState.queue.length > 0 && available > 0) {
      const item = toastState.queue.shift();
      showToast(item.id, item.message, item.type, item.duration, item.action);
    }
  }

  function toast(message, options = {}) {
    const {
      type = 'default',
      duration = toastState.defaultDuration,
      action = null
    } = options;

    const id = `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const container = initToastContainer();
    const visible = container.querySelectorAll('[data-toast-id]').length;

    if (visible >= toastState.maxVisible) {
      // Add to queue
      toastState.queue.push({ id, message, type, duration, action });
    } else {
      // Show immediately
      showToast(id, message, type, duration, action);
    }

    return id;
  }
  
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, m => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;" }[m]));
  }
  
  function setRoute(hash) {
    location.hash = hash;
  }
  
  function route() {
    const h = location.hash.replace("#", "");
    if (!state.me) return renderLogin();
    if (state.me && state.me.password_change_required) {
      showPasswordChangeModal();
      return;
    }
    if (state.me && state.me.mfa_setup_required) {
      showMfaSetupRequiredModal();
      return;
    }
    if (!h || h === "/") return renderVlanList();
    if (h.startsWith("/vlan/")) {
      const id = h.split("/")[2];
      return renderVlanDetail(id);
    }
    if (h === "/audit-logs") return renderAuditLogs();
    renderVlanList();
  }
  
  async function init() {
    try {
      state.me = await api("/api/me", { loadingKey: "init-me" });
      if (state.me && state.me.password_change_required) {
        showPasswordChangeModal();
      } else if (state.me && state.me.mfa_setup_required) {
        // MFA setup is required - show blocking modal
        showMfaSetupRequiredModal();
      }
    } catch {
      state.me = null;
    }
    window.addEventListener("hashchange", route);
    // Handle window resize to update view mode on mobile
    window.addEventListener("resize", () => {
      if (state.currentVlan) {
        const tbody = document.querySelector("#rows");
        if (tbody) {
          renderRows(tbody, state.currentVlan);
        }
      }
    });
    route();
  }
  
  // Password strength meter helper function
  function attachPasswordStrengthMeter(passwordInput, strengthContainer) {
    let debounceTimer;
    
    passwordInput.addEventListener("input", async () => {
      clearTimeout(debounceTimer);
      const password = passwordInput.value;
      
      if (!password) {
        strengthContainer.innerHTML = '<div class="text-xs text-zinc-500 mt-1">Password must contain: uppercase, lowercase, number, and special character</div>';
        return;
      }
      
      // Debounce API calls
      debounceTimer = setTimeout(async () => {
        try {
          const result = await api("/api/auth/password-strength", {
            method: "POST",
            body: { password },
            loadingKey: "password-strength"
          });
          
          const levelColors = {
            weak: "bg-red-500",
            fair: "bg-orange-500",
            good: "bg-yellow-500",
            strong: "bg-green-500"
          };
          
          const levelLabels = {
            weak: "Weak",
            fair: "Fair",
            good: "Good",
            strong: "Strong"
          };
          
          const color = levelColors[result.level] || "bg-zinc-500";
          const label = levelLabels[result.level] || "Weak";
          
          strengthContainer.innerHTML = `
            <div class="mt-2">
              <div class="flex items-center gap-2 mb-1">
                <div class="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                  <div class="h-full ${color} transition-all duration-300" style="width: ${result.score}%"></div>
                </div>
                <span class="text-xs font-medium ${color.replace('bg-', 'text-')}">${label}</span>
              </div>
              ${result.feedback && result.feedback.length > 0 ? `
                <div class="text-xs text-zinc-400 mt-1">
                  ${result.feedback.map(f => `• ${f}`).join('<br>')}
                </div>
              ` : ''}
            </div>
          `;
        } catch (e) {
          // Silently fail - don't show error for strength check
        }
      }, 300);
    });
  }

  function showPasswordChangeModal() {
    const m = modalShell("Setup Required", `
      <div class="space-y-3">
        <div class="text-sm text-zinc-300">
          You are logging in with the default admin account. Please choose a new username and password.
        </div>
        <div>
          <label class="text-xs text-zinc-400">New Username</label>
          <input id="newUsername" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
        </div>
        <div>
          <label class="text-xs text-zinc-400">Current Password</label>
          <input id="currentPassword" type="password" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
        </div>
        <div>
          <label class="text-xs text-zinc-400">New Password</label>
          <input id="newPassword" type="password" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
          <div id="newPasswordStrength" class="text-xs text-zinc-500 mt-1">Password must contain: uppercase, lowercase, number, and special character</div>
        </div>
        <div>
          <label class="text-xs text-zinc-400">Confirm New Password</label>
          <input id="confirmPassword" type="password" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <button id="save" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
            </svg>
            Save
          </button>
        </div>
      </div>
    `);
    
    // Prevent closing the modal until password is changed
    const closeBtn = m.querySelector("#close");
    if (closeBtn) closeBtn.style.display = "none";
    m.onclick = null; // Disable click-outside-to-close
    
    // Attach password strength meter
    const newPasswordInput = m.querySelector("#newPassword");
    const strengthContainer = m.querySelector("#newPasswordStrength");
    attachPasswordStrengthMeter(newPasswordInput, strengthContainer);
    
    const saveBtn = m.querySelector("#save");
    saveBtn.onclick = async () => {
      const newUsername = m.querySelector("#newUsername").value.trim();
      const currentPassword = m.querySelector("#currentPassword").value;
      const newPassword = m.querySelector("#newPassword").value;
      const confirmPassword = m.querySelector("#confirmPassword").value;
      
      setButtonLoading(saveBtn, true, "Save");
      
      try {
        if (!newUsername || newUsername.length < 3) {
          throw new Error("Username must be at least 3 characters");
        }
        if (!newPassword || newPassword.length < 8) {
          throw new Error("Password must be at least 8 characters");
        }
        if (newPassword !== confirmPassword) {
          throw new Error("Passwords do not match");
        }
        
        // Change username first
        await api("/api/auth/change-username", { method:"POST", body:{ new_username: newUsername }, loadingKey: "change-username" });
        
        // Then change password
        await api("/api/auth/change-password", { method:"POST", body:{ current_password: currentPassword, new_password: newPassword }, loadingKey: "change-password" });
        
        // Refresh user info
        state.me = await api("/api/me", { loadingKey: "me" });
        
        toast("Username and password updated", { type: "success" });
        m.remove();
        setRoute("#/");
        route();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(saveBtn, false);
      }
    };
  }

  function showMfaSetupRequiredModal() {
    // Blocking modal for when MFA setup is required (MFA_ENFORCE_ALL)
    let mfaSecret = null;
    const m = modalShell("MFA Setup Required", `
      <div class="space-y-4">
        <div class="text-sm text-zinc-300 bg-yellow-900/20 border border-yellow-800 rounded-lg p-3">
          <div class="font-medium mb-1">Two-factor authentication is now required</div>
          <div>You must set up 2FA to continue using the application. This is a security requirement.</div>
        </div>
        <div id="mfaSetupSection" class="hidden space-y-3">
          <div class="text-sm font-medium text-zinc-200">Step 1: Scan QR Code</div>
          <div class="flex justify-center bg-white p-4 rounded-lg">
            <img id="mfaQrCode" src="" alt="QR Code" class="max-w-full" />
          </div>
          <div class="text-sm text-zinc-400 text-center">
            Or enter this code manually: <code id="mfaManualCode" class="bg-zinc-800 px-2 py-1 rounded font-mono text-zinc-200"></code>
          </div>
          <div class="text-sm font-medium text-zinc-200 mt-4">Step 2: Verify Setup</div>
          <div>
            <label class="text-xs text-zinc-400">Enter 6-digit code from your app</label>
            <input id="mfaVerifyCode" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="000000" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 text-center text-xl tracking-widest" />
          </div>
          <div class="flex justify-end gap-2 pt-2">
            <button id="completeMfaSetupBtn" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm flex items-center gap-2">
              Complete Setup
            </button>
          </div>
        </div>
        <div id="mfaInitialSection" class="space-y-3">
          <div class="flex justify-end gap-2 pt-2">
            <button id="startMfaSetupBtn" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm flex items-center gap-2">
              Start Setup
            </button>
          </div>
        </div>
      </div>
    `);
    document.body.appendChild(m);
    
    // Make modal non-dismissible (user must complete setup)
    const closeBtn = m.querySelector('[data-modal-close]');
    if (closeBtn) {
      closeBtn.style.display = 'none';
    }
    const backdrop = m.querySelector('.fixed.inset-0');
    if (backdrop) {
      backdrop.onclick = null; // Prevent closing on backdrop click
    }
    
    const startBtn = m.querySelector("#startMfaSetupBtn");
    const setupSection = m.querySelector("#mfaSetupSection");
    const initialSection = m.querySelector("#mfaInitialSection");
    const completeBtn = m.querySelector("#completeMfaSetupBtn");
    const verifyCodeInput = m.querySelector("#mfaVerifyCode");
    
    startBtn.onclick = async () => {
      setButtonLoading(startBtn, true, "Setting up...");
      try {
        const setup = await api("/api/auth/mfa/setup", { 
          method: "POST", 
          loadingKey: "mfa-setup" 
        });
        mfaSecret = setup.secret;
        
        // Show QR code
        const qrImg = m.querySelector("#mfaQrCode");
        qrImg.src = `data:image/png;base64,${setup.qr_code}`;
        
        // Show manual code
        const manualCode = m.querySelector("#mfaManualCode");
        manualCode.textContent = setup.manual_entry_key;
        
        initialSection.classList.add("hidden");
        setupSection.classList.remove("hidden");
        verifyCodeInput.focus();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(startBtn, false);
      }
    };
    
    completeBtn.onclick = async () => {
      const code = verifyCodeInput.value.trim().replace(/\D/g, "");
      if (code.length !== 6) {
        toast("Please enter a 6-digit code", { type: "warning" });
        return;
      }
      
      if (!mfaSecret) {
        toast("Setup error. Please try again.", { type: "error" });
        return;
      }
      
      setButtonLoading(completeBtn, true, "Verifying...");
      try {
        await api("/api/auth/mfa/complete-setup", { 
          method: "POST", 
          body: { secret: mfaSecret, code }, 
          loadingKey: "mfa-complete" 
        });
        state.me = await api("/api/me", { loadingKey: "me" });
        toast("2FA enabled successfully", { type: "success" });
        m.remove();
        route(); // Re-route to refresh the page
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(completeBtn, false);
      }
    };
    
    verifyCodeInput.addEventListener("input", (e) => {
      e.target.value = e.target.value.replace(/\D/g, "");
      if (e.target.value.length === 6) {
        completeBtn.click();
      }
    });
  }

  function showMfaSettingsModal() {
    const mfaEnabled = state.me && state.me.mfa_enabled;
    const m = modalShell("Two-Factor Authentication", `
      <div class="space-y-4">
        ${mfaEnabled ? `
          <div class="bg-green-900/20 border border-green-800 rounded-lg p-3">
            <div class="flex items-center gap-2 text-green-300">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
              </svg>
              <span class="font-medium">2FA is enabled</span>
            </div>
            <div class="text-sm text-zinc-300 mt-1">Your account is protected with two-factor authentication.</div>
          </div>
          <div>
            <label class="text-xs text-zinc-400">Current Password (required to disable)</label>
            <input id="disableMfaPassword" type="password" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
          </div>
          <div class="flex justify-end gap-2 pt-2">
            <button id="disableMfaBtn" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-red-600 text-white font-medium hover:opacity-90 text-sm flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
              Disable 2FA
            </button>
          </div>
        ` : `
          <div class="text-sm text-zinc-300">
            Two-factor authentication adds an extra layer of security to your account. 
            You'll need to enter a code from your authenticator app (like Google Authenticator or Authy) when logging in.
          </div>
          <div id="mfaSetupSection" class="hidden space-y-3">
            <div class="text-sm font-medium text-zinc-200">Step 1: Scan QR Code</div>
            <div class="flex justify-center bg-white p-4 rounded-lg">
              <img id="mfaQrCode" src="" alt="QR Code" class="max-w-full" />
            </div>
            <div class="text-sm text-zinc-400">
              Or enter this code manually: <code id="mfaManualCode" class="bg-zinc-800 px-2 py-1 rounded font-mono text-zinc-200"></code>
            </div>
            <div class="text-sm font-medium text-zinc-200 mt-4">Step 2: Verify Setup</div>
            <div>
              <label class="text-xs text-zinc-400">Enter 6-digit code from your app</label>
              <input id="mfaVerifyCode" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="000000" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 text-center text-xl tracking-widest" />
            </div>
            <div class="flex justify-end gap-2 pt-2">
              <button id="cancelMfaSetupBtn" class="min-h-[44px] px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-900 font-medium text-sm">Cancel</button>
              <button id="completeMfaSetupBtn" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm flex items-center gap-2">
                Complete Setup
              </button>
            </div>
          </div>
          <div id="mfaInitialSection" class="space-y-3">
            <div class="flex justify-end gap-2 pt-2">
              <button id="startMfaSetupBtn" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm flex items-center gap-2">
                Enable 2FA
              </button>
            </div>
          </div>
        `}
      </div>
    `);
    document.body.appendChild(m);

    if (mfaEnabled) {
      const disableBtn = m.querySelector("#disableMfaBtn");
      const passwordInput = m.querySelector("#disableMfaPassword");
      
      disableBtn.onclick = async () => {
        const password = passwordInput.value;
        if (!password) {
          toast("Please enter your password", { type: "warning" });
          return;
        }
        
        setButtonLoading(disableBtn, true, "Disabling...");
        try {
          await api("/api/auth/mfa/disable", { 
            method: "POST", 
            body: { password }, 
            loadingKey: "disable-mfa" 
          });
          state.me = await api("/api/me", { loadingKey: "me" });
          toast("2FA disabled successfully", { type: "success" });
          m.remove();
          showMfaSettingsModal(); // Refresh modal
        } catch (e) {
          toast(e.message, { type: "error" });
        } finally {
          setButtonLoading(disableBtn, false);
        }
      };
    } else {
      let mfaSecret = null;
      
      const startBtn = m.querySelector("#startMfaSetupBtn");
      const setupSection = m.querySelector("#mfaSetupSection");
      const initialSection = m.querySelector("#mfaInitialSection");
      const cancelBtn = m.querySelector("#cancelMfaSetupBtn");
      const completeBtn = m.querySelector("#completeMfaSetupBtn");
      const verifyCodeInput = m.querySelector("#mfaVerifyCode");
      
      startBtn.onclick = async () => {
        setButtonLoading(startBtn, true, "Setting up...");
        try {
          const setup = await api("/api/auth/mfa/setup", { 
            method: "POST", 
            loadingKey: "mfa-setup" 
          });
          mfaSecret = setup.secret;
          
          // Show QR code
          const qrImg = m.querySelector("#mfaQrCode");
          qrImg.src = `data:image/png;base64,${setup.qr_code}`;
          
          // Show manual code
          const manualCode = m.querySelector("#mfaManualCode");
          manualCode.textContent = setup.manual_entry_key;
          
          initialSection.classList.add("hidden");
          setupSection.classList.remove("hidden");
          verifyCodeInput.focus();
        } catch (e) {
          toast(e.message, { type: "error" });
        } finally {
          setButtonLoading(startBtn, false);
        }
      };
      
      cancelBtn.onclick = () => {
        m.remove();
      };
      
      completeBtn.onclick = async () => {
        const code = verifyCodeInput.value.trim().replace(/\D/g, "");
        if (code.length !== 6) {
          toast("Please enter a 6-digit code", { type: "warning" });
          return;
        }
        
        if (!mfaSecret) {
          toast("Setup error. Please try again.", { type: "error" });
          return;
        }
        
        setButtonLoading(completeBtn, true, "Verifying...");
        try {
          await api("/api/auth/mfa/complete-setup", { 
            method: "POST", 
            body: { secret: mfaSecret, code }, 
            loadingKey: "mfa-complete" 
          });
          state.me = await api("/api/me", { loadingKey: "me" });
          toast("2FA enabled successfully", { type: "success" });
          m.remove();
          showMfaSettingsModal(); // Refresh modal
        } catch (e) {
          toast(e.message, { type: "error" });
        } finally {
          setButtonLoading(completeBtn, false);
        }
      };
      
      verifyCodeInput.addEventListener("input", (e) => {
        e.target.value = e.target.value.replace(/\D/g, "");
        if (e.target.value.length === 6) {
          completeBtn.click();
        }
      });
    }
  }
  
  function showMfaQrCodeModal(mfaSetup, username) {
    const m = modalShell("MFA Setup for New User", `
      <div class="space-y-4">
        <div class="bg-blue-900/20 border border-blue-800 rounded-lg p-3">
          <div class="text-sm text-zinc-300">
            MFA has been enabled for user <strong>${username}</strong>. 
            Share this QR code with the user so they can set up their authenticator app.
          </div>
        </div>
        <div class="text-sm font-medium text-zinc-200">QR Code</div>
        <div class="flex justify-center bg-white p-4 rounded-lg">
          <img src="data:image/png;base64,${mfaSetup.qr_code}" alt="QR Code" class="max-w-full" />
        </div>
        <div class="text-sm text-zinc-400">
          Or enter this code manually: <code class="bg-zinc-800 px-2 py-1 rounded font-mono text-zinc-200">${mfaSetup.manual_entry_key}</code>
        </div>
        <div class="text-xs text-zinc-500">
          <strong>Important:</strong> The user will need to scan this QR code with their authenticator app (Google Authenticator, Authy, etc.) 
          before they can log in. Save this information securely.
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <button id="closeMfaQrBtn" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm">
            Close
          </button>
        </div>
      </div>
    `);
    document.body.appendChild(m);
    
    m.querySelector("#closeMfaQrBtn").onclick = () => m.remove();
  }
  
  async function performExportWithMfa(url, exportType = "data") {
    // Check if user has MFA enabled (required for MFA_REQUIRED_FOR_EXPORT check)
    const userHasMfa = state.me && state.me.mfa_enabled;
    
    // Show MFA verification modal if required
    return new Promise((resolve, reject) => {
      const m = modalShell("MFA Verification Required", `
        <div class="space-y-4">
          <div class="text-sm text-zinc-300">
            Please enter your 2FA code to proceed with the export.
          </div>
          <div>
            <label class="text-xs text-zinc-400">2FA Code</label>
            <input id="exportMfaCode" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="000000" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 text-center text-2xl tracking-widest" />
          </div>
          <div class="flex justify-end gap-2 pt-2">
            <button id="cancelExportMfaBtn" class="min-h-[44px] px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-900 font-medium text-sm">Cancel</button>
            <button id="verifyExportMfaBtn" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm flex items-center gap-2">
              Verify & Export
            </button>
          </div>
        </div>
      `);
      document.body.appendChild(m);
      
      const verifyBtn = m.querySelector("#verifyExportMfaBtn");
      const cancelBtn = m.querySelector("#cancelExportMfaBtn");
      const codeInput = m.querySelector("#exportMfaCode");
      
      codeInput.focus();
      
      const performVerify = async () => {
        const code = codeInput.value.trim().replace(/\D/g, "");
        if (code.length !== 6) {
          toast("Please enter a 6-digit code", { type: "warning" });
          return;
        }
        
        setButtonLoading(verifyBtn, true, "Verifying...");
        try {
          const res = await api("/api/export/verify-mfa", {
            method: "POST",
            body: { code },
            loadingKey: "export-mfa-verify"
          });
          
          // Add export token to URL
          const separator = url.includes("?") ? "&" : "?";
          const finalUrl = `${url}${separator}export_token=${encodeURIComponent(res.export_token)}`;
          
          m.remove();
          window.location.href = finalUrl;
          resolve();
        } catch (e) {
          toast(e.message, { type: "error" });
          setButtonLoading(verifyBtn, false);
        }
      };
      
      verifyBtn.onclick = performVerify;
      cancelBtn.onclick = () => {
        m.remove();
        reject(new Error("Export cancelled"));
      };
      
      codeInput.addEventListener("input", (e) => {
        e.target.value = e.target.value.replace(/\D/g, "");
        if (e.target.value.length === 6) {
          performVerify();
        }
      });
      
      codeInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && codeInput.value.length === 6) {
          performVerify();
        }
      });
    });
  }

  function appRoot() {
    return document.getElementById("app");
  }
  
  function topbar() {
    const isAdmin = state.me && state.me.role === "admin";
    return el(`
      <div class="sticky top-0 z-10 bg-zinc-950/80 backdrop-blur border-b border-zinc-800">
        <div class="max-w-6xl mx-auto px-4 py-3 flex items-center gap-3">
          <img id="logoBtn" src="/logo.png" alt="Mini-IPAM" class="h-6 cursor-pointer hover:opacity-80 transition-opacity" />
          <div class="flex-1"></div>
          ${isAdmin ? '<button id="iconLibraryBtn" class="text-xs sm:text-sm px-3 sm:px-4 py-2 sm:py-2.5 rounded-md border border-zinc-800 hover:bg-zinc-900 min-h-[44px] font-medium flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">' + 
            '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>' +
            '<span>Icon Library</span></button>' : ''}
          ${isAdmin ? '<button id="manageUsersBtn" class="text-xs sm:text-sm px-3 sm:px-4 py-2 sm:py-2.5 rounded-md border border-zinc-800 hover:bg-zinc-900 min-h-[44px] font-medium flex items-center gap-2 transition-all duration-200">' + 
            '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>' +
            '<span>Manage Users</span></button>' : ''}
          <button id="auditLogsBtn" class="text-xs sm:text-sm px-3 sm:px-4 py-2 sm:py-2.5 rounded-md border border-zinc-800 hover:bg-zinc-900 min-h-[44px] font-medium flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
            <span>Audit Logs</span></button>
          <button id="exportBtn" class="text-xs sm:text-sm px-3 sm:px-4 py-2 sm:py-2.5 rounded-md border border-zinc-800 hover:bg-zinc-900 min-h-[44px] font-medium flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
            <span>Export</span></button>
          <button id="settingsBtn" class="text-xs sm:text-sm px-3 sm:px-4 py-2 sm:py-2.5 rounded-md border border-zinc-800 hover:bg-zinc-900 min-h-[44px] font-medium flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
            <span>Settings</span></button>
          <button id="logoutBtn" class="text-xs sm:text-sm px-3 sm:px-4 py-2 sm:py-2.5 rounded-md border border-zinc-800 hover:bg-zinc-900 min-h-[44px] font-medium flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
            <span>Logout</span></button>
        </div>
      </div>
    `);
  }
  
  function renderLogin() {
    const root = appRoot();
    root.innerHTML = "";
    const node = el(`
      <div class="min-h-full flex flex-col items-center justify-center p-6">
        <img src="/logo.png" alt="Mini-IPAM Logo" class="mb-6 max-w-xs h-auto" />
        <div class="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-2xl p-6 shadow-xl">
          <div class="text-lg font-semibold">Sign in</div>
          <div class="text-sm text-zinc-400 mt-1">Log in with your credentials.</div>
  
          <div class="mt-5 space-y-3">
            <div>
              <label class="text-xs text-zinc-400">Username</label>
              <input id="u" placeholder="Enter your username" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 placeholder:text-zinc-600" />
            </div>
            <div>
              <label class="text-xs text-zinc-400">Password</label>
              <input id="p" type="password" placeholder="Enter your password" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 placeholder:text-zinc-600" />
            </div>
            <button id="loginBtn" class="w-full mt-2 bg-white text-zinc-900 rounded-lg px-3 py-2.5 font-medium hover:opacity-90 min-h-[44px]">
              Login
            </button>
          </div>
        </div>
      </div>
    `);
    root.appendChild(node);

    const usernameInput = node.querySelector("#u");
    const passwordInput = node.querySelector("#p");
    const loginBtn = node.querySelector("#loginBtn");

    let mfaRequired = false;
    let mfaSetupRequired = false;
    let storedUsername = "";
    let storedPassword = "";
    let mfaSetupSecret = null;

    const performLogin = async () => {
      const username = usernameInput.value.trim();
      const password = passwordInput.value;
      const mfaCodeInput = node.querySelector("#mfaCode");
      const mfaCode = mfaCodeInput ? mfaCodeInput.value.trim() : null;
      
      if (!username || !password) {
        toast("Please enter username and password", { type: "warning" });
        return;
      }
      
      if (mfaRequired && !mfaCode) {
        toast("Please enter your 2FA code", { type: "warning" });
        return;
      }
      
      if (mfaSetupRequired && !mfaCode) {
        toast("Please enter the verification code from your authenticator app", { type: "warning" });
        return;
      }
      
      setButtonLoading(loginBtn, true, mfaRequired ? "Verifying..." : mfaSetupRequired ? "Completing setup..." : "Login");
      
      try {
        // If we're in MFA setup mode and have a code, complete setup and login
        if (mfaSetupRequired && mfaCode && mfaSetupSecret) {
          const res = await api("/api/auth/mfa/complete-setup-and-login", {
            method: "POST",
            body: {
              username: storedUsername,
              password: storedPassword,
              secret: mfaSetupSecret,
              code: mfaCode
            },
            loadingKey: "mfa-complete-login"
          });
          
          state.me = res.user;
          
          if (res.user.password_change_required) {
            showPasswordChangeModal();
          } else {
            toast("2FA enabled and logged in successfully", { type: "success" });
            setRoute("#/");
            route();
          }
          return;
        }
        
        // Normal login flow
        const res = await api("/api/auth/login", { 
          method:"POST", 
          body:{ username, password, mfa_code: mfaCode || null }, 
          loadingKey: "login" 
        });
        
        // Check if MFA setup is required (MFA_ENFORCE_ALL but user hasn't set up MFA)
        if (res.mfa_setup_required === true) {
          mfaSetupRequired = true;
          storedUsername = username;
          storedPassword = password;
          
          // Get MFA setup data
          try {
            const setupRes = await api("/api/auth/mfa/setup-during-login", {
              method: "POST",
              body: { username, password },
              loadingKey: "mfa-setup-login"
            });
            
            mfaSetupSecret = setupRes.secret;
            
            // Show MFA setup UI
            const mfaSetupSection = el(`
              <div id="mfaSetupSection" class="mt-3 space-y-4">
                <div class="text-sm text-zinc-300 bg-yellow-900/20 border border-yellow-800 rounded-lg p-3">
                  <div class="font-medium mb-1">Two-factor authentication setup required</div>
                  <div>You need to set up 2FA to continue. Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)</div>
                </div>
                <div class="flex justify-center bg-white p-4 rounded-lg">
                  <img src="data:image/png;base64,${setupRes.qr_code}" alt="QR Code" class="max-w-full" />
                </div>
                <div class="text-sm text-zinc-400 text-center">
                  Or enter this code manually: <code class="bg-zinc-800 px-2 py-1 rounded font-mono text-zinc-200">${setupRes.manual_entry_key}</code>
                </div>
                <div>
                  <label class="text-xs text-zinc-400">Enter 6-digit code from your app</label>
                  <input id="mfaCode" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="000000" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 placeholder:text-zinc-600 text-center text-2xl tracking-widest" />
                </div>
              </div>
            `);
            
            const loginForm = node.querySelector(".space-y-3");
            if (loginForm && !node.querySelector("#mfaSetupSection")) {
              loginForm.appendChild(mfaSetupSection);
              const mfaInput = node.querySelector("#mfaCode");
              if (mfaInput) {
                mfaInput.focus();
                mfaInput.addEventListener("input", (e) => {
                  e.target.value = e.target.value.replace(/\D/g, "");
                  if (e.target.value.length === 6) {
                    performLogin();
                  }
                });
              }
            }
            
            setButtonLoading(loginBtn, false);
            return;
          } catch (setupError) {
            toast(setupError.message, { type: "error" });
            mfaSetupRequired = false;
            setButtonLoading(loginBtn, false);
            return;
          }
        }
        
        // Check if MFA is required (user has MFA enabled)
        if (res.mfa_required === true) {
          mfaRequired = true;
          storedUsername = username;
          storedPassword = password;
          
          // Show MFA input field
          const mfaSection = el(`
            <div id="mfaSection" class="mt-3 space-y-3">
              <div class="text-sm text-zinc-300 bg-blue-900/20 border border-blue-800 rounded-lg p-3">
                Two-factor authentication is required. Enter the 6-digit code from your authenticator app.
              </div>
              <div>
                <label class="text-xs text-zinc-400">2FA Code</label>
                <input id="mfaCode" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="000000" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 placeholder:text-zinc-600 text-center text-2xl tracking-widest" />
              </div>
            </div>
          `);
          
          const loginForm = node.querySelector(".space-y-3");
          if (loginForm && !node.querySelector("#mfaSection")) {
            loginForm.appendChild(mfaSection);
            const mfaInput = node.querySelector("#mfaCode");
            if (mfaInput) {
              mfaInput.focus();
              mfaInput.addEventListener("input", (e) => {
                e.target.value = e.target.value.replace(/\D/g, "");
                if (e.target.value.length === 6) {
                  performLogin();
                }
              });
            }
          }
          
          setButtonLoading(loginBtn, false);
          return;
        }
        
        state.me = res.user;
        
        if (res.user.password_change_required) {
          showPasswordChangeModal();
        } else {
          toast("Logged in", { type: "success" });
          setRoute("#/");
          route();
        }
      } catch (e) {
        // Check if this is an invalid MFA code error
        const isInvalidMfaCode = e.message && (
          e.message.includes("Invalid two-factor authentication code") ||
          e.message.includes("Invalid verification code")
        );
        
        if (isInvalidMfaCode && (mfaRequired || mfaSetupRequired)) {
          // For invalid MFA codes, just show notification and keep the field visible
          toast("Invalid code. Please try again.", { type: "error" });
          // Clear the input field but keep it visible
          const mfaCodeInput = node.querySelector("#mfaCode");
          if (mfaCodeInput) {
            mfaCodeInput.value = "";
            mfaCodeInput.focus();
          }
        } else {
          // For other errors, show error and reset MFA state
          toast(e.message, { type: "error" });
          // Reset MFA state on error
          mfaRequired = false;
          mfaSetupRequired = false;
          mfaSetupSecret = null;
          const mfaSection = node.querySelector("#mfaSection");
          if (mfaSection) {
            mfaSection.remove();
          }
          const mfaSetupSection = node.querySelector("#mfaSetupSection");
          if (mfaSetupSection) {
            mfaSetupSection.remove();
          }
        }
      } finally {
        setButtonLoading(loginBtn, false);
      }
    };

    loginBtn.onclick = performLogin;

    // Allow Enter key to submit login form
    const handleEnterKey = (e) => {
      if (e.key === "Enter") {
        performLogin();
      }
    };
    usernameInput.addEventListener("keydown", handleEnterKey);
    passwordInput.addEventListener("keydown", handleEnterKey);
  }
  
  async function loadVlans() {
    state.vlans = await api("/api/vlans");
  }
  
  function renderVlanList() {
    const root = appRoot();
    root.innerHTML = "";
    const tb = topbar();
    root.appendChild(tb);
  
    tb.querySelector("#logoutBtn").onclick = async () => {
      const btn = tb.querySelector("#logoutBtn");
      setButtonLoading(btn, true, "Logout");
      try {
        await api("/api/auth/logout", { method:"POST", loadingKey: "logout" });
        state.me = null;
        toast("Logged out", { type: "success" });
        route();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(btn, false);
      }
    };
    tb.querySelector("#exportBtn").onclick = async () => {
      try {
        const url = "/api/export/data";
        // Check if MFA verification is required
        if (state.me && state.me.mfa_verify_before_export && state.me.mfa_enabled) {
          await performExportWithMfa(url, "data");
        } else if (state.me && state.me.mfa_required_for_export && !state.me.mfa_enabled) {
          toast("MFA must be enabled to export data. Please enable 2FA in Settings.", { type: "error" });
        } else {
          window.location.href = url;
        }
      } catch (e) {
        if (e.message !== "Export cancelled") {
          toast(e.message || "Export failed", { type: "error" });
        }
      }
    };
    const iconLibraryBtn = tb.querySelector("#iconLibraryBtn");
    if (iconLibraryBtn) {
      iconLibraryBtn.onclick = () => openIconLibraryModal();
    }
    const manageUsersBtn = tb.querySelector("#manageUsersBtn");
    if (manageUsersBtn) {
      manageUsersBtn.onclick = () => openManageUsersModal();
    }
    const auditLogsBtn = tb.querySelector("#auditLogsBtn");
    if (auditLogsBtn) {
      auditLogsBtn.onclick = () => setRoute("#/audit-logs");
    }
    const settingsBtn = tb.querySelector("#settingsBtn");
    if (settingsBtn) {
      settingsBtn.onclick = () => showMfaSettingsModal();
    }
    tb.querySelector("#logoBtn").onclick = () => {
      setRoute("#/");
      route();
    };

    const content = el(`
      <div class="max-w-6xl mx-auto px-4 py-6">
        <div class="flex items-end justify-between gap-3">
          <div>
            <div class="text-2xl font-semibold tracking-tight">VLANs</div>
            <div class="text-sm text-zinc-400">Track assigned IPs per subnet.</div>
          </div>
          ${state.me && state.me.role !== "readonly" ? `
          <button id="createVlanBtn" class="bg-white text-zinc-900 rounded-lg px-4 py-2.5 font-medium hover:opacity-90 min-h-[44px] text-sm flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
            </svg>
            Create new VLAN
          </button>
          ` : ''}
        </div>
  
        <div id="cards" class="mt-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div>
      </div>
    `);
  
    root.appendChild(content);
  
    const createVlanBtn = content.querySelector("#createVlanBtn");
    if (createVlanBtn) {
      createVlanBtn.onclick = () => openVlanModal();
    }
  
    (async () => {
      try {
        await loadVlans();
        renderVlanCards(content.querySelector("#cards"));
      } catch (e) {
        toast(e.message, { type: "error" });
      }
    })();
  }
  
  function meterBar(used, total) {
    const pct = total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0;
    // Color thresholds: green < 50%, yellow 50-80%, red > 80%
    let colorClass = "bg-green-500";
    if (pct >= 80) {
      colorClass = "bg-red-500";
    } else if (pct >= 50) {
      colorClass = "bg-yellow-500";
    }
    return `
      <div class="h-2 rounded-full bg-zinc-800 overflow-hidden">
        <div class="h-2 ${colorClass}" style="width:${pct}%"></div>
      </div>
    `;
  }
  
  function renderVlanCards(container) {
    container.innerHTML = "";
    for (const v of state.vlans) {
      const used = v.derived.used;
      const total = v.derived.total_usable;
      const pct = total > 0 ? Math.round((used / total) * 100) : 0;
      const card = el(`
        <div class="relative bg-zinc-900 border border-zinc-800 rounded-2xl p-4 hover:bg-zinc-900/70 transition-all duration-200 hover:scale-[1.01] hover:border-zinc-700 animate-fadeIn">
          <button class="w-full text-left" data-card-btn>
            <div class="flex items-start justify-between gap-3">
              <div>
                <div class="font-semibold">${escapeHtml(v.name)}</div>
                <div class="text-xs text-zinc-400 mt-1">${escapeHtml(v.subnet_cidr)}${v.vlan_id ? ` · VLAN ${v.vlan_id}` : ""}</div>
              </div>
            </div>
            <div class="mt-3">${meterBar(used, total)}</div>
            <div class="mt-3 flex items-center justify-between gap-3 text-xs text-zinc-400">
              <div class="flex gap-3">
                <div><span class="text-zinc-200">${used}</span> used</div>
                <div><span class="text-zinc-200">${v.derived.reserved}</span> reserved</div>
              </div>
              <div class="flex items-center gap-2 text-zinc-300">
                <div class="text-zinc-400">${used}/${total}</div>
                <div class="font-medium">${pct}%</div>
              </div>
            </div>
          </button>
          ${state.me && state.me.role !== "readonly" ? `
          <button class="absolute top-3 right-3 p-2 bg-white text-zinc-900 rounded-lg hover:opacity-90 transition-all duration-200 hover:scale-[1.05] w-8 h-8 flex items-center justify-center" data-add-btn title="Add IP">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
            </svg>
          </button>
          ` : ''}
        </div>
      `);
      card.querySelector("[data-card-btn]").onclick = () => setRoute(`#/vlan/${v.id}`);
      const addBtn = card.querySelector("[data-add-btn]");
      if (addBtn) {
        addBtn.onclick = async (e) => {
          e.stopPropagation();
          const btn = e.target.closest("[data-add-btn]");
          setButtonLoading(btn, true, `<svg class="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path></svg>`);
          try {
            const fullVlan = await api(`/api/vlans/${v.id}`, { loadingKey: `vlan-${v.id}` });
            openAssignmentModal(fullVlan);
          } catch (e) {
            toast(e.message, { type: "error" });
          } finally {
            setButtonLoading(btn, false);
          }
        };
      }
      container.appendChild(card);
    }
  }
  
  function modalShell(title, innerHtml) {
    const m = el(`
      <div class="fixed inset-0 z-50 flex items-center justify-center p-0 sm:p-4 bg-black/60 animate-fadeIn">
        <div class="w-full h-full sm:h-auto sm:max-h-[90vh] sm:max-w-xl bg-zinc-900 border-0 sm:border border-zinc-800 rounded-none sm:rounded-2xl shadow-2xl overflow-hidden flex flex-col animate-scaleIn">
          <div class="px-4 sm:px-5 py-4 border-b border-zinc-800 flex items-center justify-between flex-shrink-0">
            <div class="font-semibold text-lg">${escapeHtml(title)}</div>
            <button class="min-w-[44px] min-h-[44px] flex items-center justify-center text-zinc-400 hover:text-zinc-200 text-xl transition-all duration-200 hover:scale-110 hover:rotate-90" id="close">✕</button>
          </div>
          <div class="flex-1 overflow-y-auto p-4 sm:p-5">${innerHtml}</div>
        </div>
      </div>
    `);
    m.querySelector("#close").onclick = () => m.remove();
    m.onclick = (e) => { if (e.target === m) m.remove(); };
    document.body.appendChild(m);
    return m;
  }
  
  function openVlanModal(existing=null) {
    const isEdit = !!existing;
    const m = modalShell(isEdit ? "Edit VLAN" : "Create VLAN", `
      <div class="space-y-3">
        <div>
          <label class="text-xs text-zinc-400">Name</label>
          <input id="name" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label class="text-xs text-zinc-400">VLAN ID (optional)</label>
            <input id="vid" type="number" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
          </div>
          <div>
            <label class="text-xs text-zinc-400">Subnet CIDR</label>
            <input id="cidr" placeholder="192.168.10.0/24" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 mono" />
          </div>
        </div>
        <div class="flex flex-col sm:flex-row justify-end gap-2 pt-2">
          <button id="cancel" class="min-h-[44px] px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 text-sm font-medium flex items-center gap-2 transition-all duration-200">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
            Cancel
          </button>
          <button id="save" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
            ${isEdit ? `
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
              </svg>
              Save
            ` : `
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
              </svg>
              Create
            `}
          </button>
        </div>
      </div>
    `);
  
    const name = m.querySelector("#name");
    const vid = m.querySelector("#vid");
    const cidr = m.querySelector("#cidr");
  
    if (existing) {
      name.value = existing.name;
      vid.value = existing.vlan_id ?? "";
      cidr.value = existing.subnet_cidr;
    }
  
    m.querySelector("#cancel").onclick = () => m.remove();
    const saveBtn = m.querySelector("#save");
    saveBtn.onclick = async () => {
      setButtonLoading(saveBtn, true);
      try {
        const payload = {
          name: name.value.trim(),
          vlan_id: vid.value ? parseInt(vid.value, 10) : null,
          subnet_cidr: cidr.value.trim()
        };
        if (!payload.name || !payload.subnet_cidr) throw new Error("Name and CIDR are required");

        if (!existing) {
          await api("/api/vlans", { method:"POST", body: payload, loadingKey: "create-vlan" });
          toast("VLAN created", { type: "success" });
        } else {
          await api(`/api/vlans/${existing.id}`, { method:"PATCH", body: payload, loadingKey: "update-vlan" });
          toast("VLAN updated", { type: "success" });
        }
        m.remove();
        route();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(saveBtn, false);
      }
    };
  }
  
  async function renderVlanDetail(vlanId) {
    const root = appRoot();
    root.innerHTML = "";
    const tb = topbar();
    root.appendChild(tb);
  
    tb.querySelector("#logoutBtn").onclick = async () => {
      const btn = tb.querySelector("#logoutBtn");
      setButtonLoading(btn, true, "Logout");
      try {
        await api("/api/auth/logout", { method:"POST", loadingKey: "logout" });
        state.me = null;
        route();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(btn, false);
      }
    };
    tb.querySelector("#exportBtn").onclick = () => window.location.href = "/api/export/data";
    const iconLibraryBtn = tb.querySelector("#iconLibraryBtn");
    if (iconLibraryBtn) {
      iconLibraryBtn.onclick = () => openIconLibraryModal();
    }
    const manageUsersBtn = tb.querySelector("#manageUsersBtn");
    if (manageUsersBtn) {
      manageUsersBtn.onclick = () => openManageUsersModal();
    }
    const auditLogsBtn = tb.querySelector("#auditLogsBtn");
    if (auditLogsBtn) {
      auditLogsBtn.onclick = () => setRoute("#/audit-logs");
    }
    const settingsBtn = tb.querySelector("#settingsBtn");
    if (settingsBtn) {
      settingsBtn.onclick = () => showMfaSettingsModal();
    }
    tb.querySelector("#logoBtn").onclick = () => {
      setRoute("#/");
      route();
    };

    const wrap = el(`
      <div class="max-w-6xl mx-auto px-4 py-6">
        <button id="back" class="px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 text-sm text-zinc-200 hover:text-zinc-100 min-h-[44px] font-medium transition-all duration-200 hover:scale-[1.02] flex items-center gap-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
          </svg>
          Back
        </button>

        <div id="header" class="mt-4"></div>

        <div class="mt-6 space-y-3">
          <div class="flex flex-col sm:flex-row gap-3">
            <input id="search" placeholder="Search IP / hostname / tag / notes..." class="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2.5 outline-none focus:border-zinc-600 min-h-[44px]" />
            <select id="typeFilter" class="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2.5 outline-none focus:border-zinc-600 min-h-[44px]">
              <option value="all">All types</option>
            </select>
          </div>
          <div class="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
            ${state.me && state.me.role !== "readonly" ? `
            <button id="nextBtn" class="px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 min-h-[44px] text-sm font-medium transition-all duration-200 hover:scale-[1.02]">Next available</button>
            <button id="addBtn" class="px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 min-h-[44px] text-sm flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
              </svg>
              Add
            </button>
            ` : ''}
            <div class="flex gap-2">
              <div class="relative">
                <button id="exportBtn" class="px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 min-h-[44px] text-sm font-medium flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                  </svg>
                  Export
                </button>
                <div id="exportMenu" class="hidden absolute top-full mt-1 right-0 bg-zinc-900 border border-zinc-800 rounded-lg shadow-lg z-50 min-w-[120px] animate-slideUp">
                  <button class="exportFormatBtn w-full text-left px-4 py-2 hover:bg-zinc-800 text-sm transition-all duration-200" data-format="csv">CSV</button>
                  <button class="exportFormatBtn w-full text-left px-4 py-2 hover:bg-zinc-800 text-sm transition-all duration-200" data-format="json">JSON</button>
                  <button class="exportFormatBtn w-full text-left px-4 py-2 hover:bg-zinc-800 text-sm transition-all duration-200" data-format="excel">Excel</button>
                </div>
              </div>
              ${state.me && state.me.role !== "readonly" ? `
              <button id="importBtn" class="px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 min-h-[44px] text-sm font-medium flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                </svg>
                Import
              </button>
              ` : ''}
            </div>
            <div class="flex-1"></div>
            <button id="viewToggle" class="md:hidden px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 min-h-[44px] text-sm flex items-center justify-center gap-2 transition-all duration-200 hover:scale-[1.02]">
              <span id="viewToggleText">Card View</span>
              <svg id="viewToggleIcon" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path>
              </svg>
            </button>
          </div>
        </div>

        <div id="tableContainer" class="mt-4 overflow-hidden rounded-2xl border border-zinc-800 hidden md:block">
          <table class="w-full text-sm">
            <thead class="bg-zinc-900 border-b border-zinc-800 text-zinc-300">
              <tr>
                <th class="text-left p-3 w-12">Icon</th>
                <th class="text-left p-3 mono">IP</th>
                <th class="text-left p-3">Hostname/Service</th>
                <th class="text-left p-3">Type</th>
                <th class="text-left p-3">Tags</th>
                <th class="text-left p-3">Notes</th>
                <th class="text-right p-3 w-24">Actions</th>
              </tr>
            </thead>
            <tbody id="rows" class="bg-zinc-950"></tbody>
          </table>
        </div>
        <div id="cardContainer" class="mt-4 space-y-3 md:hidden"></div>
      </div>
    `);

    root.appendChild(wrap);
    wrap.querySelector("#back").onclick = () => setRoute("#/");

    // Show skeleton loaders while fetching
    const tbody = wrap.querySelector("#rows");
    const cardContainer = wrap.querySelector("#cardContainer");
    for (let i = 0; i < 5; i++) {
      tbody.appendChild(skeletonTableRow());
      if (cardContainer) {
        cardContainer.appendChild(skeletonCard());
      }
    }

    let vlan;
    try {
      vlan = await api(`/api/vlans/${vlanId}`, { loadingKey: `vlan-${vlanId}` });
      state.currentVlan = vlan;
    } catch (e) {
      tbody.innerHTML = `<tr><td class="p-4 text-zinc-500 text-center" colspan="7">Failed to load VLAN: ${escapeHtml(e.message)}</td></tr>`;
      if (cardContainer) {
        cardContainer.innerHTML = `<div class="p-4 text-zinc-500 text-center bg-zinc-900 border border-zinc-800 rounded-lg">Failed to load VLAN: ${escapeHtml(e.message)}</div>`;
      }
      toast(e.message);
      return;
    }
  
    // populate type filter options
    const settings = await api("/api/settings");
    const typeSel = wrap.querySelector("#typeFilter");
    for (const t of settings.type_options) {
      typeSel.appendChild(el(`<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`));
    }
  
    wrap.querySelector("#search").oninput = (e) => {
      state.filterText = e.target.value;
      renderRows(wrap.querySelector("#rows"), vlan);
    };
    typeSel.onchange = (e) => {
      state.filterType = e.target.value;
      renderRows(wrap.querySelector("#rows"), vlan);
    };
  
    const addBtn = wrap.querySelector("#addBtn");
    const nextBtn = wrap.querySelector("#nextBtn");
    const totalUsable = vlan.derived?.total_usable ?? 0;
    
    // Disable assignment buttons if no usable hosts
    if (totalUsable === 0) {
      if (addBtn) {
        addBtn.disabled = true;
        addBtn.classList.add("opacity-50", "cursor-not-allowed");
        addBtn.title = "No usable hosts in this subnet";
      }
      if (nextBtn) {
        nextBtn.disabled = true;
        nextBtn.classList.add("opacity-50", "cursor-not-allowed");
        nextBtn.title = "No usable hosts in this subnet";
      }
    }
    
    if (addBtn) {
      addBtn.onclick = () => {
        if (totalUsable === 0) {
          toast("No usable hosts in this subnet (/31 and /32 subnets cannot have assignments)", { type: "error" });
          return;
        }
        openAssignmentModal(vlan);
      };
    }
    if (nextBtn) {
      nextBtn.onclick = async () => {
        if (totalUsable === 0) {
          toast("No usable hosts in this subnet (/31 and /32 subnets cannot have assignments)", { type: "error" });
          return;
        }
        setButtonLoading(nextBtn, true, "Next available");
        try {
          const res = await api(`/api/vlans/${vlan.id}/next-available`, { loadingKey: `next-ip-${vlan.id}` });
          if (!res.ip) {
            toast("No available IP found", { type: "info" });
            return;
          }
          openAssignmentModal(vlan, null, { presetIp: res.ip });
        } catch (e) {
          toast(e.message, { type: "error" });
        } finally {
          setButtonLoading(nextBtn, false);
        }
      };
    }

    // Export button handler
    const exportBtn = wrap.querySelector("#exportBtn");
    const exportMenu = wrap.querySelector("#exportMenu");
    let exportMenuOpen = false;
    
    exportBtn.onclick = (e) => {
      e.stopPropagation();
      exportMenuOpen = !exportMenuOpen;
      exportMenu.classList.toggle("hidden", !exportMenuOpen);
    };
    
    // Close export menu when clicking outside
    document.addEventListener("click", (e) => {
      if (!exportBtn.contains(e.target) && !exportMenu.contains(e.target)) {
        exportMenuOpen = false;
        exportMenu.classList.add("hidden");
      }
    });
    
    // Export format handlers
    wrap.querySelectorAll(".exportFormatBtn").forEach(btn => {
      btn.onclick = async (e) => {
        e.stopPropagation();
        exportMenuOpen = false;
        exportMenu.classList.add("hidden");
        
        const format = btn.dataset.format;
        const search = (state.filterText || "").trim() || null;
        const typeFilter = state.filterType && state.filterType !== "all" ? state.filterType : null;
        
        try {
          const params = new URLSearchParams({ format });
          if (search) params.append("search", search);
          if (typeFilter) params.append("type_filter", typeFilter);
          
          const url = `/api/vlans/${vlan.id}/assignments/export?${params.toString()}`;
          
          // Check if MFA verification is required
          if (state.me && state.me.mfa_verify_before_export && state.me.mfa_enabled) {
            await performExportWithMfa(url, "assignments");
          } else if (state.me && state.me.mfa_required_for_export && !state.me.mfa_enabled) {
            toast("MFA must be enabled to export data. Please enable 2FA in Settings.", { type: "error" });
          } else {
            window.location.href = url;
            toast(`Exporting as ${format.toUpperCase()}...`, { type: "info" });
          }
        } catch (e) {
          if (e.message !== "Export cancelled") {
            toast(e.message, { type: "error" });
          }
        }
      };
    });
    
    // Import button handler
    const importBtn = wrap.querySelector("#importBtn");
    if (importBtn) {
      importBtn.onclick = () => openImportModal(vlan);
    }

    // View toggle handler (only on mobile)
    const viewToggle = wrap.querySelector("#viewToggle");
    if (viewToggle) {
      // Initialize view mode based on screen size
      const isMobile = window.innerWidth < 768;
      if (isMobile && state.viewMode === "table") {
        state.viewMode = "card"; // Default to card view on mobile
      }
      
      const updateViewToggle = () => {
        const isTable = state.viewMode === "table";
        const toggleText = wrap.querySelector("#viewToggleText");
        const toggleIcon = wrap.querySelector("#viewToggleIcon");
        if (isTable) {
          toggleText.textContent = "Card View";
          toggleIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path>';
        } else {
          toggleText.textContent = "Table View";
          toggleIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"></path>';
        }
      };
      viewToggle.onclick = () => {
        state.viewMode = state.viewMode === "table" ? "card" : "table";
        updateViewToggle();
        renderRows(wrap.querySelector("#rows"), vlan);
      };
      updateViewToggle();
    }

    renderVlanHeader(wrap.querySelector("#header"), vlan);
    renderRows(wrap.querySelector("#rows"), vlan);
  }
  
  function ipToInt(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  }

  function intToIp(int) {
    return [
      (int >>> 24) & 255,
      (int >>> 16) & 255,
      (int >>> 8) & 255,
      int & 255
    ].join('.');
  }

  function renderIpRangeMap(container, vlan) {
    const d = vlan.derived;
    const usedSet = new Set(vlan.used_effective || []);
    const reservedSet = new Set(vlan.reserved_effective || []);
    
    const startInt = ipToInt(d.usable_start);
    const endInt = ipToInt(d.usable_end);
    const total = endInt - startInt + 1;
    
    // Limit visualization to reasonable size (max 256 IPs for performance)
    const maxDisplay = 256;
    const step = total > maxDisplay ? Math.ceil(total / maxDisplay) : 1;
    const displayCount = Math.ceil(total / step);
    
    const mapDiv = document.createElement("div");
    mapDiv.className = "mt-4 p-4 bg-zinc-900 border border-zinc-800 rounded-lg";
    
    const mapTitle = document.createElement("div");
    mapTitle.className = "text-xs text-zinc-400 mb-3";
    mapTitle.textContent = "IP Range Map";
    mapDiv.appendChild(mapTitle);
    
    const mapGrid = document.createElement("div");
    mapGrid.className = "flex flex-wrap gap-0.5";
    mapGrid.style.maxHeight = "120px";
    mapGrid.style.overflowY = "auto";
    
    for (let i = 0; i < displayCount; i++) {
      const ipInt = startInt + (i * step);
      if (ipInt > endInt) break;
      
      const ip = intToIp(ipInt);
      const isUsed = usedSet.has(ip);
      const isReserved = reservedSet.has(ip);
      
      const cell = document.createElement("div");
      cell.className = "w-2 h-2 rounded-sm";
      cell.title = `${ip} - ${isUsed ? 'Used' : isReserved ? 'Reserved' : 'Free'}`;
      
      if (isUsed) {
        cell.className += " bg-blue-500";
      } else if (isReserved) {
        cell.className += " bg-orange-500";
      } else {
        cell.className += " bg-zinc-700";
      }
      
      mapGrid.appendChild(cell);
    }
    
    mapDiv.appendChild(mapGrid);
    
    const legend = document.createElement("div");
    legend.className = "mt-3 flex flex-wrap gap-4 text-xs text-zinc-400";
    legend.innerHTML = `
      <div class="flex items-center gap-2">
        <div class="w-3 h-3 rounded-sm bg-blue-500"></div>
        <span>Used</span>
      </div>
      <div class="flex items-center gap-2">
        <div class="w-3 h-3 rounded-sm bg-orange-500"></div>
        <span>Reserved</span>
      </div>
      <div class="flex items-center gap-2">
        <div class="w-3 h-3 rounded-sm bg-zinc-700"></div>
        <span>Free</span>
      </div>
      ${total > maxDisplay ? `<span class="text-zinc-500">Showing ${displayCount} of ${total} IPs</span>` : ''}
    `;
    mapDiv.appendChild(legend);
    
    container.appendChild(mapDiv);
  }

  function renderVlanHeader(container, vlan) {
    const d = vlan.derived;
    const used = vlan.assignments.filter(a => !a.archived).length;
    const reserved = vlan.reserved_effective ? vlan.reserved_effective.length : 0;
    const total = d.total_usable;
    const pct = total > 0 ? Math.round((used / total) * 100) : 0;
    
    // Clear container
    container.innerHTML = "";
    
    // Create main wrapper
    const wrapper = document.createElement("div");
    wrapper.className = "flex flex-col md:flex-row md:items-end md:justify-between gap-3";
    
    // Left section
    const leftDiv = document.createElement("div");
    
    const titleDiv = document.createElement("div");
    titleDiv.className = "text-2xl font-semibold tracking-tight";
    titleDiv.textContent = vlan.name;
    leftDiv.appendChild(titleDiv);
    
    const infoDiv = document.createElement("div");
    infoDiv.className = "text-sm text-zinc-400 mt-1";
    
    const subnetSpan = document.createElement("span");
    subnetSpan.className = "mono";
    subnetSpan.textContent = vlan.subnet_cidr;
    infoDiv.appendChild(subnetSpan);
    
    if (vlan.vlan_id) {
      infoDiv.appendChild(document.createTextNode(` · VLAN ${vlan.vlan_id}`));
    }
    
    infoDiv.appendChild(document.createTextNode(" · GW "));
    
    const gwSpan = document.createElement("span");
    gwSpan.className = "mono";
    gwSpan.textContent = d.gateway_ip || d.gateway_suggested || "-";
    infoDiv.appendChild(gwSpan);
    
    leftDiv.appendChild(infoDiv);
    
    const usableDiv = document.createElement("div");
    usableDiv.className = "text-xs text-zinc-500 mt-1";
    
    if (total === 0) {
      usableDiv.appendChild(document.createTextNode("No usable hosts ("));
      const cidrSpan = document.createElement("span");
      cidrSpan.className = "mono text-orange-400";
      cidrSpan.textContent = "/31 or /32 subnet";
      usableDiv.appendChild(cidrSpan);
      usableDiv.appendChild(document.createTextNode(")"));
    } else {
      usableDiv.appendChild(document.createTextNode("Usable: "));
      
      const usableStartSpan = document.createElement("span");
      usableStartSpan.className = "mono";
      usableStartSpan.textContent = d.usable_start;
      usableDiv.appendChild(usableStartSpan);
      
      usableDiv.appendChild(document.createTextNode(" → "));
      
      const usableEndSpan = document.createElement("span");
      usableEndSpan.className = "mono";
      usableEndSpan.textContent = d.usable_end;
      usableDiv.appendChild(usableEndSpan);
      
      usableDiv.appendChild(document.createTextNode(` (${total})`));
    }
    leftDiv.appendChild(usableDiv);
    
    wrapper.appendChild(leftDiv);
    
    // Right section with enhanced breakdown
    const rightDiv = document.createElement("div");
    rightDiv.className = "min-w-[240px]";
    
    const statsDiv = document.createElement("div");
    statsDiv.className = "text-xs text-zinc-400 mb-3 space-y-1";
    statsDiv.innerHTML = `
      <div class="flex justify-between items-center">
        <span>Used:</span>
        <span class="text-zinc-200 font-medium">${used} (${pct}%)</span>
      </div>
      <div class="flex justify-between items-center">
        <span>Reserved:</span>
        <span class="text-zinc-200 font-medium">${reserved}</span>
      </div>
      <div class="flex justify-between items-center">
        <span>Free:</span>
        <span class="text-zinc-200 font-medium">${Math.max(0, total - used - reserved)}</span>
      </div>
    `;
    rightDiv.appendChild(statsDiv);
    
    // Enhanced breakdown with separate bars
    const breakdownDiv = document.createElement("div");
    breakdownDiv.className = "space-y-1.5";
    
    // Used bar
    const usedBarDiv = document.createElement("div");
    usedBarDiv.className = "relative h-2 rounded-full bg-zinc-800 overflow-hidden";
    const usedBarFill = document.createElement("div");
    usedBarFill.className = "h-2 bg-blue-500";
    usedBarFill.style.width = `${total > 0 ? Math.min(100, (used / total) * 100) : 0}%`;
    usedBarDiv.appendChild(usedBarFill);
    breakdownDiv.appendChild(usedBarDiv);
    
    // Reserved bar (stacked on top of used)
    if (reserved > 0) {
      const reservedBarDiv = document.createElement("div");
      reservedBarDiv.className = "relative h-2 rounded-full bg-zinc-800 overflow-hidden";
      const reservedBarFill = document.createElement("div");
      reservedBarFill.className = "h-2 bg-orange-500";
      reservedBarFill.style.width = `${total > 0 ? Math.min(100, (reserved / total) * 100) : 0}%`;
      reservedBarDiv.appendChild(reservedBarFill);
      breakdownDiv.appendChild(reservedBarDiv);
    }
    
    // Overall usage meter
    const overallMeter = el(meterBar(used, total));
    breakdownDiv.appendChild(overallMeter);
    
    rightDiv.appendChild(breakdownDiv);
    
    wrapper.appendChild(rightDiv);
    container.appendChild(wrapper);
    
    // Add IP range map below
    renderIpRangeMap(container, vlan);
  }
  
  function pill(text) {
    return `<span class="text-xs px-2 py-1 rounded-full border border-zinc-800 bg-zinc-900 transition-colors duration-150">${escapeHtml(text)}</span>`;
  }
  
  function tagChip(t) {
    return `<span class="text-xs px-2 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-200 transition-colors duration-150">${escapeHtml(t)}</span>`;
  }
  
  function matchesFilter(a) {
    const q = (state.filterText || "").trim().toLowerCase();
    const typeOk = state.filterType === "all" ? true : a.type === state.filterType;
    if (!typeOk) return false;
    if (!q) return !a.archived;
  
    const hay = [
      a.ip, a.hostname, a.type,
      ...(a.tags || []),
      a.notes || ""
    ].join(" ").toLowerCase();
    return !a.archived && hay.includes(q);
  }
  
  function renderRows(tbody, vlan) {
    const list = vlan.assignments.filter(matchesFilter).sort((x,y) => x.ip.localeCompare(y.ip));
    const cardContainer = document.querySelector("#cardContainer");
    const tableContainer = document.querySelector("#tableContainer");

    // Show/hide containers based on view mode and screen size
    const isMobile = window.innerWidth < 768; // md breakpoint
    const useCardView = isMobile ? (state.viewMode === "card") : false;
    
    if (useCardView) {
      tableContainer.classList.add("hidden");
      cardContainer.classList.remove("hidden");
      renderCards(cardContainer, list, vlan);
    } else {
      tableContainer.classList.remove("hidden");
      cardContainer.classList.add("hidden");
      renderTableRows(tbody, list, vlan);
    }
  }

  function renderTableRows(tbody, list, vlan) {
    tbody.innerHTML = "";
    
    if (list.length === 0) {
      tbody.appendChild(el(`<tr><td class="p-4 text-zinc-500 text-center" colspan="7">No assignments match your filters.</td></tr>`));
      return;
    }

    for (const a of list) {
      // Create icon cell using DOM methods
      const iconTd = document.createElement("td");
      iconTd.className = "p-3";
      if (a.icon?.data_base64) {
        const img = document.createElement("img");
        img.className = "w-8 h-8 rounded-md border border-zinc-800 object-cover object-center";
        // Escape mime_type to prevent XSS in data URI
        const safeMimeType = escapeHtml(a.icon.mime_type || "image/png");
        img.src = `data:${safeMimeType};base64,${a.icon.data_base64}`;
        iconTd.appendChild(img);
      } else {
        const div = document.createElement("div");
        div.className = "w-8 h-8 rounded-md border border-zinc-800 bg-zinc-900";
        iconTd.appendChild(div);
      }

      const tr = el(`
        <tr class="border-b border-zinc-900 hover:bg-zinc-900/30 transition-colors duration-150 animate-fadeIn">
          <td class="p-3 mono">${escapeHtml(a.ip)}</td>
          <td class="p-3">${escapeHtml(a.hostname || "")}</td>
          <td class="p-3">${pill(a.type)}</td>
          <td class="p-3">
            <div class="flex flex-wrap gap-1">
              ${(a.tags || []).slice(0, 8).map(tagChip).join("")}
            </div>
          </td>
          <td class="p-3 text-zinc-300">${escapeHtml((a.notes || "").slice(0, 80))}</td>
          <td class="p-3 text-right">
            <div class="flex flex-row gap-2 items-center justify-end">
              <button class="min-w-[44px] min-h-[44px] px-3 py-2 rounded-md border border-zinc-800 hover:bg-zinc-950 flex items-center justify-center transition-all duration-200 hover:scale-[1.05]" data-edit title="Edit">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                </svg>
              </button>
              <button class="min-w-[44px] min-h-[44px] px-3 py-2 rounded-md border border-zinc-800 hover:bg-zinc-950 flex items-center justify-center transition-all duration-200 hover:scale-[1.05]" data-del title="Delete">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                </svg>
              </button>
            </div>
          </td>
        </tr>
      `);
      
      // Insert icon cell as first child
      tr.insertBefore(iconTd, tr.firstChild);
  
      tr.querySelector("[data-edit]").onclick = () => openAssignmentModal(vlan, a);
      tr.querySelector("[data-del]").onclick = async () => {
        if (!confirm(`Delete ${a.ip}?`)) return;
        const delBtn = tr.querySelector("[data-del]");
        setButtonLoading(delBtn, true);
        
        // Store assignment data for undo
        const deletedAssignment = {
          vlanId: vlan.id,
          assignment: {
            ip: a.ip,
            hostname: a.hostname,
            type: a.type,
            tags: a.tags || [],
            notes: a.notes || "",
            icon: a.icon
          }
        };
        
        try {
          await api(`/api/vlans/${vlan.id}/assignments/${a.id}`, { method:"DELETE", loadingKey: `delete-${a.id}` });
          
          // Show toast with undo option
          toast(`Deleted ${a.ip}`, { 
            type: "success",
            duration: 5000,
            action: {
              label: "Undo",
              onClick: async () => {
                try {
                  await api(`/api/vlans/${deletedAssignment.vlanId}/assignments`, {
                    method: "POST",
                    body: deletedAssignment.assignment,
                    loadingKey: `undo-${deletedAssignment.vlanId}`
                  });
                  toast("Restored", { type: "success" });
                  const fresh = await api(`/api/vlans/${deletedAssignment.vlanId}`, { loadingKey: `vlan-${deletedAssignment.vlanId}` });
                  state.currentVlan = fresh;
                  Object.assign(vlan, fresh);
                  const tbody = document.querySelector("#rows");
                  renderRows(tbody, vlan);
                } catch (e) {
                  toast(e.message, { type: "error" });
                }
              }
            }
          });
          
                  const fresh = await api(`/api/vlans/${vlan.id}`, { loadingKey: `vlan-${vlan.id}` });
                  state.currentVlan = fresh;
                  Object.assign(vlan, fresh);
                  const tbody = document.querySelector("#rows");
                  if (tbody) renderRows(tbody, vlan);
        } catch (e) { 
          toast(e.message, { type: "error" });
        } finally {
          setButtonLoading(delBtn, false);
        }
      };

      tbody.appendChild(tr);
    }
  }

  function renderCards(container, list, vlan) {
    container.innerHTML = "";
    
    if (list.length === 0) {
      container.appendChild(el(`<div class="p-4 text-zinc-500 text-center bg-zinc-900 border border-zinc-800 rounded-lg">No assignments match your filters.</div>`));
      return;
    }

    for (const a of list) {
      const card = el(`
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4 space-y-3 transition-all duration-200 hover:border-zinc-700 animate-fadeIn">
          <div class="flex items-start gap-3">
            ${a.icon?.data_base64 ? 
              `<img src="data:${escapeHtml(a.icon.mime_type || "image/png")};base64,${a.icon.data_base64}" class="w-12 h-12 rounded-md border border-zinc-800 object-cover object-center flex-shrink-0" />` :
              `<div class="w-12 h-12 rounded-md border border-zinc-800 bg-zinc-950 flex-shrink-0"></div>`
            }
            <div class="flex-1 min-w-0">
              <div class="flex items-start justify-between gap-2">
                <div class="flex-1 min-w-0">
                  <div class="font-semibold mono text-base">${escapeHtml(a.ip)}</div>
                  ${a.hostname ? `<div class="text-sm text-zinc-300 mt-0.5 truncate">${escapeHtml(a.hostname)}</div>` : ''}
                </div>
                <div class="flex-shrink-0">${pill(a.type)}</div>
              </div>
            </div>
          </div>
          
          ${(a.tags || []).length > 0 ? `
            <div class="flex flex-wrap gap-1.5">
              ${(a.tags || []).map(tagChip).join("")}
            </div>
          ` : ''}
          
          ${a.notes ? `
            <div class="text-sm text-zinc-300 line-clamp-2">${escapeHtml(a.notes)}</div>
          ` : ''}
          
          <div class="flex gap-2 pt-2 border-t border-zinc-800">
            <button class="flex-1 min-h-[44px] px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 flex items-center justify-center gap-2 text-sm font-medium transition-all duration-200 hover:scale-[1.02]" data-edit>
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
              </svg>
              Edit
            </button>
            <button class="flex-1 min-h-[44px] px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 flex items-center justify-center gap-2 text-sm font-medium text-red-400 transition-all duration-200 hover:scale-[1.02]" data-del>
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
              </svg>
              Delete
            </button>
          </div>
        </div>
      `);
      
      card.querySelector("[data-edit]").onclick = () => openAssignmentModal(vlan, a);
      card.querySelector("[data-del]").onclick = async () => {
        if (!confirm(`Delete ${a.ip}?`)) return;
        const delBtn = card.querySelector("[data-del]");
        setButtonLoading(delBtn, true);
        
        // Store assignment data for undo
        const deletedAssignment = {
          vlanId: vlan.id,
          assignment: {
            ip: a.ip,
            hostname: a.hostname,
            type: a.type,
            tags: a.tags || [],
            notes: a.notes || "",
            icon: a.icon
          }
        };
        
        try {
          await api(`/api/vlans/${vlan.id}/assignments/${a.id}`, { method:"DELETE", loadingKey: `delete-${a.id}` });
          
          // Show toast with undo option
          toast(`Deleted ${a.ip}`, { 
            type: "success",
            duration: 5000,
            action: {
              label: "Undo",
              onClick: async () => {
                try {
                  await api(`/api/vlans/${deletedAssignment.vlanId}/assignments`, {
                    method: "POST",
                    body: deletedAssignment.assignment,
                    loadingKey: `undo-${deletedAssignment.vlanId}`
                  });
                  toast("Restored", { type: "success" });
                  const fresh = await api(`/api/vlans/${deletedAssignment.vlanId}`, { loadingKey: `vlan-${deletedAssignment.vlanId}` });
                  state.currentVlan = fresh;
                  Object.assign(vlan, fresh);
                  const cardContainer = document.querySelector("#cardContainer");
                  const tbody = document.querySelector("#rows");
                  renderRows(tbody, vlan);
                } catch (e) {
                  toast(e.message, { type: "error" });
                }
              }
            }
          });
          
          const fresh = await api(`/api/vlans/${vlan.id}`, { loadingKey: `vlan-${vlan.id}` });
          state.currentVlan = fresh;
          Object.assign(vlan, fresh);
          const cardContainer = document.querySelector("#cardContainer");
          const tbody = document.querySelector("#rows");
          if (tbody) renderRows(tbody, vlan);
        } catch (e) { 
          toast(e.message, { type: "error" });
        } finally {
          setButtonLoading(delBtn, false);
        }
      };

      container.appendChild(card);
    }
  }
  
  function openCreateUserModal() {
    const m = modalShell("Create User", `
      <div class="space-y-3">
        <div>
          <label class="text-xs text-zinc-400">Username</label>
          <input id="username" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
          <div class="text-xs text-zinc-500 mt-1">Must be at least 3 characters</div>
        </div>
        <div>
          <label class="text-xs text-zinc-400">Password</label>
          <input id="password" type="password" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
          <div id="passwordStrength" class="text-xs text-zinc-500 mt-1">Password must contain: uppercase, lowercase, number, and special character</div>
        </div>
        <div>
          <label class="text-xs text-zinc-400">Role</label>
          <select id="role" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600">
            <option value="readonly">Read Only</option>
            <option value="readwrite">Read/Write</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <div class="flex items-center gap-2">
          <input type="checkbox" id="mfaEnabled" class="w-4 h-4 rounded border-zinc-800 bg-zinc-950 text-white focus:ring-2 focus:ring-zinc-600" />
          <label for="mfaEnabled" class="text-xs text-zinc-400 cursor-pointer">Enable MFA (Two-Factor Authentication)</label>
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <button id="cancel" class="px-4 py-2 rounded-lg border border-zinc-800 hover:bg-zinc-950 flex items-center gap-2 transition-all duration-200 min-h-[44px]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
            Cancel
          </button>
          <button id="save" class="px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 flex items-center gap-2 transition-all duration-200 hover:scale-[1.02] min-h-[44px]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
            </svg>
            Create
          </button>
        </div>
      </div>
    `);

    const username = m.querySelector("#username");
    const password = m.querySelector("#password");
    const role = m.querySelector("#role");
    const mfaEnabled = m.querySelector("#mfaEnabled");
    
    // Attach password strength meter
    const strengthContainer = m.querySelector("#passwordStrength");
    attachPasswordStrengthMeter(password, strengthContainer);

    m.querySelector("#cancel").onclick = () => m.remove();
    const saveBtn = m.querySelector("#save");
    saveBtn.onclick = async () => {
      setButtonLoading(saveBtn, true, "Create");
      try {
        const payload = {
          username: username.value.trim(),
          password: password.value,
          role: role.value,
          mfa_enabled: mfaEnabled.checked
        };
        
        if (!payload.username || payload.username.length < 3) {
          throw new Error("Username must be at least 3 characters");
        }
        if (!payload.password || payload.password.length < 8) {
          throw new Error("Password must be at least 8 characters");
        }

        const response = await api("/api/users", { method:"POST", body: payload, loadingKey: "create-user" });
        toast("User created", { type: "success" });
        m.remove();
        
        // If MFA was enabled, show QR code modal
        if (response.mfa_setup) {
          showMfaQrCodeModal(response.mfa_setup, payload.username);
        }
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(saveBtn, false);
      }
    };
  }

  async function openManageUsersModal() {
    const m = modalShell("Manage Users", `
      <div class="space-y-4">
        <div class="flex justify-between items-center">
          <h3 class="text-sm font-medium text-zinc-300">Users</h3>
          <button id="createUserBtn" class="px-3 py-1.5 rounded-lg bg-white text-zinc-900 text-xs font-medium hover:opacity-90 flex items-center gap-2 transition-all duration-200">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
            </svg>
            Create User
          </button>
        </div>
        <div id="usersList" class="space-y-2 max-h-96 overflow-y-auto">
          <div class="text-center text-zinc-500 py-8">Loading users...</div>
        </div>
      </div>
    `);

    const usersList = m.querySelector("#usersList");
    const createUserBtn = m.querySelector("#createUserBtn");
    
    createUserBtn.onclick = () => {
      m.remove();
      openCreateUserModal();
    };

    async function loadUsers() {
      try {
        usersList.innerHTML = '<div class="text-center text-zinc-500 py-8">Loading users...</div>';
        const response = await api("/api/users", { method: "GET", loadingKey: "load-users" });
        const users = response.users || [];
        
        if (users.length === 0) {
          usersList.innerHTML = '<div class="text-center text-zinc-500 py-8">No users found</div>';
          return;
        }

        usersList.innerHTML = "";
        users.forEach(user => {
          const roleColors = {
            admin: "bg-purple-500/20 text-purple-300 border-purple-500/30",
            readwrite: "bg-blue-500/20 text-blue-300 border-blue-500/30",
            readonly: "bg-zinc-500/20 text-zinc-300 border-zinc-500/30"
          };
          const roleLabels = {
            admin: "Admin",
            readwrite: "Read/Write",
            readonly: "Read Only"
          };
          
          const lastLogin = user.last_login_at ? new Date(user.last_login_at) : null;
          const daysSinceLogin = lastLogin ? Math.floor((Date.now() - lastLogin.getTime()) / (1000 * 60 * 60 * 24)) : null;
          const lastLoginText = lastLogin 
            ? `${lastLogin.toLocaleDateString()} ${lastLogin.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
            : "Never";
          const lastLoginClass = !lastLogin 
            ? "text-zinc-500" 
            : daysSinceLogin > 90 
              ? "text-red-400" 
              : daysSinceLogin > 30 
                ? "text-yellow-400" 
                : "text-zinc-400";
          
          const userCard = el(`
            <div class="bg-zinc-950 border border-zinc-800 rounded-lg p-4 space-y-3">
              <div class="flex items-start justify-between">
                <div class="flex-1">
                  <div class="flex items-center gap-2 mb-1">
                    <span class="font-medium text-zinc-100">${escapeHtml(user.username)}</span>
                    ${user.disabled ? '<span class="text-xs px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30">Disabled</span>' : ''}
                    ${user.mfa_enabled ? '<span class="text-xs px-2 py-0.5 rounded bg-green-500/20 text-green-300 border border-green-500/30">MFA</span>' : ''}
                  </div>
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="text-xs px-2 py-0.5 rounded border ${roleColors[user.role]}">${roleLabels[user.role]}</span>
                    <span class="text-xs text-zinc-500">Created: ${new Date(user.created_at).toLocaleDateString()}</span>
                  </div>
                  <div class="mt-1">
                    <span class="text-xs ${lastLoginClass}">Last login: ${escapeHtml(lastLoginText)}</span>
                    ${daysSinceLogin !== null && daysSinceLogin > 30 ? `<span class="text-xs text-zinc-500 ml-1">(${daysSinceLogin} days ago)</span>` : ''}
                  </div>
                </div>
                <div class="flex items-center gap-1">
                  <button class="user-action-btn p-2 rounded hover:bg-zinc-800 transition-colors" data-action="toggle" data-user-id="${user.id}" data-disabled="${user.disabled}" title="${user.disabled ? 'Enable' : 'Disable'}">
                    <svg class="w-4 h-4 ${user.disabled ? 'text-green-400' : 'text-yellow-400'}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${user.disabled ? 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' : 'M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z'}"></path>
                    </svg>
                  </button>
                  <button class="user-action-btn p-2 rounded hover:bg-zinc-800 transition-colors" data-action="username" data-user-id="${user.id}" data-username="${escapeHtml(user.username)}" title="Edit Username">
                    <svg class="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                    </svg>
                  </button>
                  <button class="user-action-btn p-2 rounded hover:bg-zinc-800 transition-colors" data-action="password" data-user-id="${user.id}" data-username="${escapeHtml(user.username)}" title="Change Password">
                    <svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path>
                    </svg>
                  </button>
                  <button class="user-action-btn p-2 rounded hover:bg-zinc-800 transition-colors" data-action="role" data-user-id="${user.id}" data-username="${escapeHtml(user.username)}" data-role="${user.role}" title="Change Role">
                    <svg class="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"></path>
                    </svg>
                  </button>
                  <button class="user-action-btn p-2 rounded hover:bg-zinc-800 transition-colors text-red-400" data-action="delete" data-user-id="${user.id}" data-username="${escapeHtml(user.username)}" title="Delete User">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                    </svg>
                  </button>
                </div>
              </div>
            </div>
          `);
          
          usersList.appendChild(userCard);
        });

        // Attach event handlers
        usersList.querySelectorAll(".user-action-btn").forEach(btn => {
          btn.onclick = async () => {
            const action = btn.dataset.action;
            const userId = btn.dataset.userId;
            const username = btn.dataset.username;
            
            if (action === "toggle") {
              const isDisabled = btn.dataset.disabled === "true";
              if (confirm(`Are you sure you want to ${isDisabled ? 'enable' : 'disable'} user "${username}"?`)) {
                setButtonLoading(btn, true);
                try {
                  await api(`/api/users/${userId}`, {
                    method: "PATCH",
                    body: { disabled: !isDisabled },
                    loadingKey: "toggle-user"
                  });
                  toast(`User ${isDisabled ? 'enabled' : 'disabled'}`, { type: "success" });
                  loadUsers();
                } catch (e) {
                  toast(e.message, { type: "error" });
                } finally {
                  setButtonLoading(btn, false);
                }
              }
            } else if (action === "username") {
              const usernameModal = modalShell(`Edit Username: ${username}`, `
                <div class="space-y-3">
                  <div>
                    <label class="text-xs text-zinc-400">New Username</label>
                    <input id="newUsername" value="${escapeHtml(username)}" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
                    <div class="text-xs text-zinc-500 mt-1">Must be at least 3 characters</div>
                  </div>
                  <div class="flex justify-end gap-2 pt-2">
                    <button id="cancel" class="px-4 py-2 rounded-lg border border-zinc-800 hover:bg-zinc-950 flex items-center gap-2 transition-all duration-200 min-h-[44px]">
                      Cancel
                    </button>
                    <button id="save" class="px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 flex items-center gap-2 transition-all duration-200 hover:scale-[1.02] min-h-[44px]">
                      Update Username
                    </button>
                  </div>
                </div>
              `);
              
              const newUsernameInput = usernameModal.querySelector("#newUsername");
              newUsernameInput.select();
              
              usernameModal.querySelector("#cancel").onclick = () => usernameModal.remove();
              const saveBtn = usernameModal.querySelector("#save");
              saveBtn.onclick = async () => {
                setButtonLoading(saveBtn, true);
                try {
                  const newUsername = newUsernameInput.value.trim();
                  if (!newUsername || newUsername.length < 3) {
                    throw new Error("Username must be at least 3 characters");
                  }
                  if (newUsername === username) {
                    throw new Error("Username is unchanged");
                  }
                  await api(`/api/users/${userId}`, {
                    method: "PATCH",
                    body: { username: newUsername },
                    loadingKey: "change-username"
                  });
                  toast("Username updated", { type: "success" });
                  usernameModal.remove();
                  loadUsers();
                } catch (e) {
                  toast(e.message, { type: "error" });
                } finally {
                  setButtonLoading(saveBtn, false);
                }
              };
            } else if (action === "password") {
              const passwordModal = modalShell(`Change Password: ${username}`, `
                <div class="space-y-3">
                  <div>
                    <label class="text-xs text-zinc-400">New Password</label>
                    <input id="newPassword" type="password" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
                    <div id="passwordStrength" class="text-xs text-zinc-500 mt-1">Password must contain: uppercase, lowercase, number, and special character</div>
                  </div>
                  <div class="flex justify-end gap-2 pt-2">
                    <button id="cancel" class="px-4 py-2 rounded-lg border border-zinc-800 hover:bg-zinc-950 flex items-center gap-2 transition-all duration-200 min-h-[44px]">
                      Cancel
                    </button>
                    <button id="save" class="px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 flex items-center gap-2 transition-all duration-200 hover:scale-[1.02] min-h-[44px]">
                      Change Password
                    </button>
                  </div>
                </div>
              `);
              
              const newPasswordInput = passwordModal.querySelector("#newPassword");
              const strengthContainer = passwordModal.querySelector("#passwordStrength");
              attachPasswordStrengthMeter(newPasswordInput, strengthContainer);
              
              passwordModal.querySelector("#cancel").onclick = () => passwordModal.remove();
              const saveBtn = passwordModal.querySelector("#save");
              saveBtn.onclick = async () => {
                setButtonLoading(saveBtn, true);
                try {
                  const newPassword = newPasswordInput.value;
                  if (!newPassword || newPassword.length < 8) {
                    throw new Error("Password must be at least 8 characters");
                  }
                  await api(`/api/users/${userId}/change-password`, {
                    method: "POST",
                    body: { new_password: newPassword },
                    loadingKey: "change-password"
                  });
                  toast("Password changed", { type: "success" });
                  passwordModal.remove();
                } catch (e) {
                  toast(e.message, { type: "error" });
                } finally {
                  setButtonLoading(saveBtn, false);
                }
              };
            } else if (action === "role") {
              const currentRole = btn.dataset.role;
              const roleModal = modalShell(`Change Role: ${username}`, `
                <div class="space-y-3">
                  <div>
                    <label class="text-xs text-zinc-400">Role</label>
                    <select id="role" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600">
                      <option value="readonly" ${currentRole === "readonly" ? "selected" : ""}>Read Only</option>
                      <option value="readwrite" ${currentRole === "readwrite" ? "selected" : ""}>Read/Write</option>
                      <option value="admin" ${currentRole === "admin" ? "selected" : ""}>Admin</option>
                    </select>
                  </div>
                  <div class="flex justify-end gap-2 pt-2">
                    <button id="cancel" class="px-4 py-2 rounded-lg border border-zinc-800 hover:bg-zinc-950 flex items-center gap-2 transition-all duration-200 min-h-[44px]">
                      Cancel
                    </button>
                    <button id="save" class="px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 flex items-center gap-2 transition-all duration-200 hover:scale-[1.02] min-h-[44px]">
                      Change Role
                    </button>
                  </div>
                </div>
              `);
              
              const roleSelect = roleModal.querySelector("#role");
              roleModal.querySelector("#cancel").onclick = () => roleModal.remove();
              const saveBtn = roleModal.querySelector("#save");
              saveBtn.onclick = async () => {
                setButtonLoading(saveBtn, true);
                try {
                  await api(`/api/users/${userId}`, {
                    method: "PATCH",
                    body: { role: roleSelect.value },
                    loadingKey: "change-role"
                  });
                  toast("Role changed", { type: "success" });
                  roleModal.remove();
                  loadUsers();
                } catch (e) {
                  toast(e.message, { type: "error" });
                } finally {
                  setButtonLoading(saveBtn, false);
                }
              };
            } else if (action === "delete") {
              if (confirm(`Are you sure you want to delete user "${username}"? This action cannot be undone.`)) {
                setButtonLoading(btn, true);
                try {
                  await api(`/api/users/${userId}`, {
                    method: "DELETE",
                    loadingKey: "delete-user"
                  });
                  toast("User deleted", { type: "success" });
                  loadUsers();
                } catch (e) {
                  toast(e.message, { type: "error" });
                } finally {
                  setButtonLoading(btn, false);
                }
              }
            }
          };
        });
      } catch (e) {
        usersList.innerHTML = `<div class="text-center text-red-400 py-8">Error loading users: ${escapeHtml(e.message)}</div>`;
      }
    }

    loadUsers();
  }

  function openIconLibraryModal() {
    const m = modalShell("Icon Library Management", `
      <div class="space-y-4">
        <div>
          <label class="text-xs text-zinc-400">Upload Multiple Icons</label>
          <input id="uploadIcons" type="file" accept="image/*" multiple class="mt-1 w-full text-sm" />
          <div class="text-xs text-zinc-500 mt-1">Select multiple image files. They will be normalized to 256×256 PNG.</div>
          <button id="uploadBtn" class="mt-2 px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm">Upload Icons</button>
        </div>
        
        <div class="border-t border-zinc-800 pt-4">
          <div class="flex items-center justify-between mb-3">
            <label class="text-xs text-zinc-400">Icon Library</label>
            <input id="librarySearch" type="text" placeholder="Search icons..." class="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-1.5 text-sm outline-none focus:border-zinc-600 w-48" />
          </div>
          <div id="iconLibraryGrid" class="grid grid-cols-4 sm:grid-cols-6 gap-3 max-h-96 overflow-y-auto p-2 bg-zinc-950 border border-zinc-800 rounded-lg">
            <!-- Icons will be loaded here -->
          </div>
        </div>
      </div>
    `);

    const uploadIcons = m.querySelector("#uploadIcons");
    const uploadBtn = m.querySelector("#uploadBtn");
    const librarySearch = m.querySelector("#librarySearch");
    const iconLibraryGrid = m.querySelector("#iconLibraryGrid");
    let allLibraryIcons = [];

    function renderLibraryIcons(filterText = "") {
      iconLibraryGrid.innerHTML = "";
      const filtered = allLibraryIcons.filter(iconInfo => {
        if (!filterText) return true;
        const search = filterText.toLowerCase();
        return iconInfo.name.toLowerCase().includes(search) || 
               iconInfo.filename.toLowerCase().includes(search);
      });
      
      if (filtered.length === 0) {
        iconLibraryGrid.innerHTML = '<div class="col-span-full text-xs text-zinc-500 text-center py-4">No icons found</div>';
        return;
      }
      
      for (const iconInfo of filtered) {
        const card = el(`
          <div class="relative group">
            <div class="aspect-square p-2 border border-zinc-800 rounded-lg bg-zinc-900 hover:border-zinc-600 transition">
              <img src="/icons/${escapeHtml(iconInfo.filename)}" class="w-full h-full object-contain" />
            </div>
            <div class="mt-1 text-xs text-zinc-400 truncate" title="${escapeHtml(iconInfo.name)}">${escapeHtml(iconInfo.name)}</div>
            <button class="absolute top-1 right-1 w-6 h-6 bg-red-600 hover:bg-red-700 rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity" data-delete-icon="${escapeHtml(iconInfo.filename)}" title="Delete">
              <svg class="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
              </svg>
            </button>
          </div>
        `);
        
        const deleteBtn = card.querySelector(`[data-delete-icon="${escapeHtml(iconInfo.filename)}"]`);
        deleteBtn.onclick = async () => {
          if (!confirm(`Delete icon "${iconInfo.name}"?`)) return;
          setButtonLoading(deleteBtn, true);
          try {
            await api(`/api/icons/${iconInfo.filename}`, { method: "DELETE", loadingKey: `delete-icon-${iconInfo.filename}` });
            toast("Icon deleted", { type: "success" });
            // Reload icons
            await loadLibraryIcons();
          } catch (e) {
            toast(e.message, { type: "error" });
          } finally {
            setButtonLoading(deleteBtn, false);
          }
        };
        
        iconLibraryGrid.appendChild(card);
      }
    }

    async function loadLibraryIcons() {
      iconLibraryGrid.innerHTML = '<div class="col-span-full text-xs text-zinc-500 text-center py-4">' + spinner("w-5 h-5").outerHTML + '<div class="mt-2">Loading icons...</div></div>';
      try {
        const iconList = await api("/api/icons/list", { loadingKey: "icons-library-list" });
        allLibraryIcons = iconList.icons || [];
        renderLibraryIcons();
      } catch (e) {
        iconLibraryGrid.innerHTML = '<div class="col-span-full text-xs text-zinc-500 text-center py-2">Failed to load icons</div>';
        toast(e.message, { type: "error" });
      }
    }

    librarySearch.oninput = (e) => {
      renderLibraryIcons(e.target.value);
    };

    uploadBtn.onclick = async () => {
      if (!uploadIcons.files || uploadIcons.files.length === 0) {
        toast("Please select at least one file", { type: "warning" });
        return;
      }
      
      setButtonLoading(uploadBtn, true, "Upload Icons");
      try {
        const fd = new FormData();
        for (let i = 0; i < uploadIcons.files.length; i++) {
          fd.append("files", uploadIcons.files[i]);
        }
        
        const result = await api("/api/icons/upload-multiple", { method: "POST", body: fd, loadingKey: "upload-icons" });
        
        if (result.success_count > 0) {
          toast(`Successfully uploaded ${result.success_count} icon(s)`, { type: "success" });
          if (result.errors && result.errors.length > 0) {
            const errorMsg = result.errors.map(e => `${e.filename}: ${e.error}`).join(", ");
            toast(`Some uploads failed: ${errorMsg}`, { type: "warning", duration: 5000 });
          }
          uploadIcons.value = "";
          await loadLibraryIcons();
        } else {
          toast("No icons were uploaded", { type: "error" });
        }
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(uploadBtn, false);
      }
    };

    // Load icons on open
    loadLibraryIcons();
  }

  function openAssignmentModal(vlan, existing=null, opts={}) {
    // Prevent opening assignment modal if no usable hosts
    const totalUsable = vlan.derived?.total_usable ?? 0;
    if (!existing && totalUsable === 0) {
      toast("No usable hosts in this subnet (/31 and /32 subnets cannot have assignments)", { type: "error" });
      return;
    }
    
    const isEdit = !!existing;
    const m = modalShell(isEdit ? "Edit assignment" : "Add assignment", `
      <div class="space-y-2.5">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-2.5">
          <div>
            <label class="text-xs text-zinc-400">IP</label>
            <div class="mt-1 flex gap-2">
              <input id="ip" placeholder="${vlan.derived ? `${escapeHtml(vlan.derived.usable_start)} - ${escapeHtml(vlan.derived.usable_end)}` : ''}" class="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 mono" />
              <button id="generateIpBtn" class="min-w-[44px] min-h-[44px] px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg hover:bg-zinc-700 text-sm whitespace-nowrap" title="Generate random available IP">🎲</button>
            </div>
            <div class="text-xs text-zinc-500 mt-1">Must be inside ${escapeHtml(vlan.subnet_cidr)} and not reserved.</div>
          </div>
          <div>
            <label class="text-xs text-zinc-400">Type</label>
            <input id="type" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
          </div>
        </div>
  
        <div>
          <label class="text-xs text-zinc-400">Hostname / Service</label>
          <input id="host" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
        </div>
  
        <div>
          <label class="text-xs text-zinc-400">Tags</label>
          <div class="relative">
            <input id="tags" placeholder="Press Enter to add tag" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
            <div id="tagsAutocomplete" class="hidden absolute z-50 w-full mt-1 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl max-h-48 overflow-y-auto"></div>
          </div>
          <div id="tagsContainer" class="mt-2 flex flex-wrap gap-2"></div>
        </div>
  
        <div>
          <label class="text-xs text-zinc-400">Notes</label>
          <textarea id="notes" rows="2" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600"></textarea>
        </div>
  
        <div>
          <label class="text-xs text-zinc-400">Icon (optional)</label>
          <div class="mt-2 space-y-2">
            <div class="relative">
              <input id="iconSearch" type="text" placeholder="Search icons..." class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm outline-none focus:border-zinc-600" />
              <svg class="absolute right-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-zinc-500 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
              </svg>
            </div>
            <div id="iconPicker" class="grid grid-cols-4 sm:grid-cols-6 gap-2 max-h-40 overflow-y-auto p-2 bg-zinc-950 border border-zinc-800 rounded-lg">
              <!-- Icons will be loaded here -->
            </div>
            <div class="flex items-center gap-2">
              <div class="text-xs text-zinc-400">Or upload custom:</div>
              <input id="icon" type="file" accept="image/*" multiple class="flex-1 text-xs" />
            </div>
            <div class="text-xs text-zinc-500">Icons are auto normalized to 256×256 PNG. You can upload multiple at once.</div>
          </div>
        </div>
  
        <div class="flex justify-end gap-2 pt-1">
          <button id="cancel" class="px-4 py-2 rounded-lg border border-zinc-800 hover:bg-zinc-950 flex items-center gap-2 transition-all duration-200 min-h-[44px]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
            Cancel
          </button>
          <button id="save" class="px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 flex items-center gap-2 transition-all duration-200 hover:scale-[1.02] min-h-[44px]">
            ${isEdit ? `
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
              </svg>
              Save
            ` : `
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
              </svg>
              Add
            `}
          </button>
        </div>
      </div>
    `);
  
    const ip = m.querySelector("#ip");
    const type = m.querySelector("#type");
    const host = m.querySelector("#host");
    const tagsInput = m.querySelector("#tags");
    const tagsContainer = m.querySelector("#tagsContainer");
    const tagsAutocomplete = m.querySelector("#tagsAutocomplete");
    const notes = m.querySelector("#notes");
    const icon = m.querySelector("#icon");
    const iconPicker = m.querySelector("#iconPicker");
    const iconSearch = m.querySelector("#iconSearch");
    const preview = m.querySelector("#preview");
    const previewText = m.querySelector("#previewText");
    const generateIpBtn = m.querySelector("#generateIpBtn");

    let iconObj = existing?.icon || null;
    let selectedIconName = null;
    let tagsList = [];
    let allIcons = []; // Store all icons for filtering
    let allAvailableTags = []; // Store all previously used tags
    let autocompleteItems = []; // Store current autocomplete suggestions
    let selectedAutocompleteIndex = -1; // Track selected autocomplete item

    // Collect all unique tags from all assignments across all vlans
    function collectAllTags() {
      const tagSet = new Set();
      state.vlans.forEach(vlan => {
        if (vlan.assignments) {
          vlan.assignments.forEach(assignment => {
            if (assignment.tags && Array.isArray(assignment.tags)) {
              assignment.tags.forEach(tag => {
                if (tag && tag.trim()) {
                  tagSet.add(tag.trim());
                }
              });
            }
          });
        }
      });
      allAvailableTags = Array.from(tagSet).sort();
    }

    function renderTags() {
      tagsContainer.innerHTML = "";
      tagsList.forEach((tag, index) => {
        // Create tag chip using DOM methods
        const chip = document.createElement("span");
        chip.className = "text-xs px-2 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-200 cursor-pointer hover:bg-zinc-800";
        chip.textContent = tag + " ×";
        chip.onclick = () => {
          tagsList.splice(index, 1);
          renderTags();
        };
        tagsContainer.appendChild(chip);
      });
    }

    function renderAutocomplete(filterText = "") {
      if (!filterText.trim()) {
        tagsAutocomplete.classList.add("hidden");
        autocompleteItems = [];
        selectedAutocompleteIndex = -1;
        return;
      }

      const filter = filterText.toLowerCase().trim();
      const filtered = allAvailableTags.filter(tag => {
        const tagLower = tag.toLowerCase();
        return tagLower.includes(filter) && !tagsList.includes(tag);
      });

      if (filtered.length === 0) {
        tagsAutocomplete.classList.add("hidden");
        autocompleteItems = [];
        selectedAutocompleteIndex = -1;
        return;
      }

      autocompleteItems = filtered;
      tagsAutocomplete.innerHTML = "";
      filtered.forEach((tag, index) => {
        const item = document.createElement("div");
        item.className = `px-3 py-2 text-sm text-zinc-200 cursor-pointer hover:bg-zinc-800 ${index === selectedAutocompleteIndex ? 'bg-zinc-800' : ''}`;
        item.textContent = tag;
        item.onclick = () => {
          selectTag(tag);
        };
        item.onmouseenter = () => {
          selectedAutocompleteIndex = index;
          renderAutocomplete(filterText);
        };
        tagsAutocomplete.appendChild(item);
      });

      tagsAutocomplete.classList.remove("hidden");
    }

    function selectTag(tag) {
      if (tag && !tagsList.includes(tag)) {
        tagsList.push(tag);
        renderTags();
        tagsInput.value = "";
        tagsAutocomplete.classList.add("hidden");
        autocompleteItems = [];
        selectedAutocompleteIndex = -1;
      }
    }

    // Initialize tag collection
    collectAllTags();

    tagsInput.addEventListener("input", (e) => {
      const value = e.target.value;
      selectedAutocompleteIndex = -1;
      renderAutocomplete(value);
    });

    tagsInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        if (selectedAutocompleteIndex >= 0 && autocompleteItems[selectedAutocompleteIndex]) {
          // Select from autocomplete
          selectTag(autocompleteItems[selectedAutocompleteIndex]);
        } else {
          // Add new tag
          const tag = tagsInput.value.trim();
          if (tag && !tagsList.includes(tag)) {
            tagsList.push(tag);
            renderTags();
            tagsInput.value = "";
            tagsAutocomplete.classList.add("hidden");
          }
        }
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        if (autocompleteItems.length > 0) {
          selectedAutocompleteIndex = Math.min(selectedAutocompleteIndex + 1, autocompleteItems.length - 1);
          renderAutocomplete(tagsInput.value);
        }
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        if (autocompleteItems.length > 0) {
          selectedAutocompleteIndex = Math.max(selectedAutocompleteIndex - 1, -1);
          renderAutocomplete(tagsInput.value);
        }
      } else if (e.key === "Escape") {
        tagsAutocomplete.classList.add("hidden");
        selectedAutocompleteIndex = -1;
      }
    });

    // Hide autocomplete when clicking outside
    const handleClickOutside = (e) => {
      if (tagsAutocomplete && !tagsAutocomplete.classList.contains("hidden")) {
        if (!tagsInput.contains(e.target) && !tagsAutocomplete.contains(e.target)) {
          tagsAutocomplete.classList.add("hidden");
        }
      }
    };
    document.addEventListener("click", handleClickOutside, true);
    
    // Clean up event listener when modal is closed
    const originalRemove = m.remove.bind(m);
    m.remove = function() {
      document.removeEventListener("click", handleClickOutside, true);
      originalRemove();
    };
  
    function setPreview(obj) {
      if (!preview) return; // Preview element removed
      if (!obj) {
        preview.innerHTML = "";
        if (previewText) previewText.textContent = "No icon";
        return;
      }
      // Clear and create img element using DOM methods
      preview.innerHTML = "";
      const img = document.createElement("img");
      img.className = "w-12 h-12 object-cover object-center";
      // Escape mime_type to prevent XSS in data URI
      const safeMimeType = escapeHtml(obj.mime_type || "image/png");
      img.src = `data:${safeMimeType};base64,${obj.data_base64}`;
      preview.appendChild(img);
      if (previewText) previewText.textContent = "Icon set";
    }

    // Function to render icons with filtering
    function renderIcons(filterText = "") {
      iconPicker.innerHTML = "";
      const filtered = allIcons.filter(iconInfo => {
        if (!filterText) return true;
        const search = filterText.toLowerCase();
        return iconInfo.name.toLowerCase().includes(search) || 
               iconInfo.filename.toLowerCase().includes(search);
      });
      
      if (filtered.length === 0) {
        iconPicker.innerHTML = '<div class="col-span-full text-xs text-zinc-500 text-center py-2">No icons match your search</div>';
        return;
      }
      
      for (const iconInfo of filtered) {
        const isSelected = selectedIconName === iconInfo.filename;
        const btn = el(`
          <button type="button" class="w-full aspect-square p-2 border rounded-lg hover:border-zinc-600 hover:bg-zinc-900 transition relative ${isSelected ? 'border-zinc-600 bg-zinc-900' : 'border-zinc-800'}" data-icon-name="${escapeHtml(iconInfo.filename)}" title="${escapeHtml(iconInfo.name)}">
            <img src="/icons/${escapeHtml(iconInfo.filename)}" class="w-full h-full object-contain" />
            ${isSelected ? `
              <div data-icon-checkmark class="absolute top-1 right-1 w-5 h-5 bg-green-600 rounded-full flex items-center justify-center shadow-lg">
                <svg class="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"></path>
                </svg>
              </div>
            ` : ''}
          </button>
        `);
        
        // Click to select directly
        btn.onclick = async () => {
          setButtonLoading(btn, true);
          try {
            // Remove previous selection (checkmark and styling)
            iconPicker.querySelectorAll("button").forEach(b => {
              b.classList.remove("border-zinc-600", "bg-zinc-900");
              b.classList.add("border-zinc-800");
              // Remove checkmark
              const checkmark = b.querySelector("[data-icon-checkmark]");
              if (checkmark) {
                checkmark.remove();
              }
            });
            
            // Add selection styling and checkmark
            btn.classList.remove("border-zinc-800");
            btn.classList.add("border-zinc-600", "bg-zinc-900");
            
            // Add checkmark
            const checkmark = el(`
              <div data-icon-checkmark class="absolute top-1 right-1 w-5 h-5 bg-green-600 rounded-full flex items-center justify-center shadow-lg">
                <svg class="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"></path>
                </svg>
              </div>
            `);
            btn.appendChild(checkmark);
            
            selectedIconName = iconInfo.filename;
            const normalized = await api(`/api/icons/${iconInfo.filename}`, { loadingKey: `icon-${iconInfo.filename}` });
            iconObj = normalized;
            setPreview(iconObj);
            toast("Icon selected", { type: "success" });
          } catch (e) {
            toast(e.message, { type: "error" });
          } finally {
            setButtonLoading(btn, false);
          }
        };
        iconPicker.appendChild(btn);
      }
    }

    // Search functionality
    iconSearch.oninput = (e) => {
      renderIcons(e.target.value);
    };

    // Load and display predefined icons
    (async () => {
      // Show loading state in icon picker
      iconPicker.innerHTML = '<div class="col-span-full text-xs text-zinc-500 text-center py-4"><div class="inline-block">' + spinner("w-5 h-5").outerHTML + '</div><div class="mt-2">Loading icons...</div></div>';
      
      try {
        const iconList = await api("/api/icons/list", { loadingKey: "icons-list" });
        allIcons = iconList.icons || [];
        renderIcons();
      } catch (e) {
        iconPicker.innerHTML = '<div class="col-span-full text-xs text-zinc-500 text-center py-2">Failed to load icons</div>';
      }
    })();
  
    if (existing) {
      ip.value = existing.ip;
      type.value = existing.type;
      host.value = existing.hostname || "";
      tagsList = [...(existing.tags || [])];
      renderTags();
      notes.value = existing.notes || "";
      setPreview(existing.icon || null);
    } else {
      type.value = "server";
      if (opts.presetIp) ip.value = opts.presetIp;
    }

    icon.onchange = async () => {
      if (!icon.files || icon.files.length === 0) return;
      
      // Handle multiple files - process first one for assignment, show message if more
      const file = icon.files[0];
      const hasMultiple = icon.files.length > 1;
      
      // Show loading in preview
      if (preview) preview.innerHTML = spinner("w-6 h-6").outerHTML;
      if (previewText) previewText.textContent = "Processing...";
      
      try {
        // Clear predefined icon selection (checkmark and styling)
        iconPicker.querySelectorAll("button").forEach(b => {
          b.classList.remove("border-zinc-600", "bg-zinc-900");
          b.classList.add("border-zinc-800");
          // Remove checkmark
          const checkmark = b.querySelector("[data-icon-checkmark]");
          if (checkmark) {
            checkmark.remove();
          }
        });
        selectedIconName = null;
        
        const fd = new FormData();
        fd.append("file", file);
        const normalized = await api("/api/icons/normalize", { method:"POST", body: fd, loadingKey: "normalize-icon" });
        iconObj = normalized;
        setPreview(iconObj);
        
        if (hasMultiple) {
          toast(`Icon normalized. Note: Only the first file was used. Use the Icon Library to upload multiple icons.`, { type: "info", duration: 5000 });
        } else {
          toast("Icon normalized", { type: "success" });
        }
      } catch (e) {
        if (preview) preview.innerHTML = "";
        if (previewText) previewText.textContent = "Failed";
        toast(e.message, { type: "error" });
      }
    };

    generateIpBtn.onclick = async () => {
      setButtonLoading(generateIpBtn, true);
      try {
        const res = await api(`/api/vlans/${vlan.id}/random-available`, { loadingKey: `random-ip-${vlan.id}` });
        if (res.ip) {
          ip.value = res.ip;
          toast("Generated random available IP", { type: "success" });
        } else {
          toast("No available IP found", { type: "info" });
        }
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(generateIpBtn, false);
      }
    };

    m.querySelector("#cancel").onclick = () => m.remove();
  
    const saveBtn = m.querySelector("#save");
    saveBtn.onclick = async () => {
      setButtonLoading(saveBtn, true);
      try {
        const payload = {
          ip: ip.value.trim(),
          hostname: host.value.trim(),
          type: type.value.trim() || "server",
          tags: tagsList,
          notes: notes.value.trim(),
          icon: iconObj
        };
        if (!payload.ip) throw new Error("IP is required");
  
        if (!existing) {
          await api(`/api/vlans/${vlan.id}/assignments`, { method:"POST", body: payload, loadingKey: `create-assignment-${vlan.id}` });
          toast("Added", { type: "success" });
        } else {
          await api(`/api/vlans/${vlan.id}/assignments/${existing.id}`, { method:"PATCH", body: payload, loadingKey: `update-assignment-${existing.id}` });
          toast("Saved", { type: "success" });
        }
  
        const fresh = await api(`/api/vlans/${vlan.id}`, { loadingKey: `vlan-${vlan.id}` });
        state.currentVlan = fresh;
        Object.assign(vlan, fresh);
  
        // rerender
        const tbody = document.querySelector("#rows");
        const header = document.querySelector("#header");
        if (header) renderVlanHeader(header, vlan);
        if (tbody) renderRows(tbody, vlan);
  
        m.remove();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(saveBtn, false);
      }
    };
  }

  function openImportModal(vlan) {
    const m = modalShell("Import Assignments", `
      <div class="space-y-4">
        <div class="text-sm text-zinc-400">
          Import assignments from CSV, JSON, or Excel file. Required columns: <code class="text-zinc-300">ip</code>. 
          Optional columns: <code class="text-zinc-300">hostname</code>, <code class="text-zinc-300">type</code>, 
          <code class="text-zinc-300">tags</code> (comma-separated), <code class="text-zinc-300">notes</code>.
        </div>
        <div>
          <label class="text-xs text-zinc-400 mb-2 block">File</label>
          <input type="file" id="importFile" accept=".csv,.json,.xlsx,.xls" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 min-h-[44px] text-sm" />
        </div>
        <div id="importResults" class="hidden space-y-2">
          <div id="importSuccess" class="text-sm text-green-400"></div>
          <div id="importErrors" class="text-sm text-red-400 space-y-1"></div>
        </div>
        <div class="flex flex-col sm:flex-row justify-end gap-2 pt-2">
          <button id="cancelImport" class="min-h-[44px] px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 text-sm font-medium">Cancel</button>
          <button id="importSubmit" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm">Import</button>
        </div>
      </div>
    `);

    const fileInput = m.querySelector("#importFile");
    const importBtn = m.querySelector("#importSubmit");
    const cancelBtn = m.querySelector("#cancelImport");
    const resultsDiv = m.querySelector("#importResults");
    const successDiv = m.querySelector("#importSuccess");
    const errorsDiv = m.querySelector("#importErrors");

    cancelBtn.onclick = () => m.remove();

    importBtn.onclick = async () => {
      if (!fileInput.files || fileInput.files.length === 0) {
        toast("Please select a file", { type: "error" });
        return;
      }

      const file = fileInput.files[0];
      const formData = new FormData();
      formData.append("file", file);

      setButtonLoading(importBtn, true, "Importing...");
      resultsDiv.classList.add("hidden");
      successDiv.textContent = "";
      errorsDiv.innerHTML = "";

      try {
        const result = await api(`/api/vlans/${vlan.id}/assignments/import`, {
          method: "POST",
          body: formData,
          loadingKey: `import-${vlan.id}`
        });

        if (result.imported > 0) {
          successDiv.textContent = `Successfully imported ${result.imported} assignment(s)`;
          toast(`Imported ${result.imported} assignment(s)`, { type: "success" });
          
          // Reload VLAN data
          const updatedVlan = await api(`/api/vlans/${vlan.id}`, { loadingKey: `vlan-${vlan.id}` });
          state.currentVlan = updatedVlan;
          Object.assign(vlan, updatedVlan);
          
          // Re-render rows
          const tbody = document.querySelector("#rows");
          if (tbody) renderRows(tbody, updatedVlan);
        }

        if (result.errors > 0) {
          let errorHtml = `<div class="font-semibold">${result.errors} error(s) occurred:</div>`;
          if (result.error_details && result.error_details.length > 0) {
            const errorList = result.error_details.slice(0, 10).map(err => {
              const row = err.row ? `Row ${err.row}: ` : "";
              const ip = err.ip ? `${err.ip} - ` : "";
              return `<div>${row}${ip}${escapeHtml(err.error)}</div>`;
            }).join("");
            errorHtml += errorList;
            if (result.error_details.length > 10) {
              errorHtml += `<div class="text-zinc-500">... and ${result.error_details.length - 10} more errors</div>`;
            }
          }
          errorsDiv.innerHTML = errorHtml;
        }

        if (result.errors > 0 || result.imported > 0) {
          resultsDiv.classList.remove("hidden");
        }

        if (result.imported > 0) {
          // Close modal after successful import
          setTimeout(() => {
            m.remove();
          }, 2000);
        }
      } catch (e) {
        toast(e.message, { type: "error" });
        errorsDiv.innerHTML = `<div>${escapeHtml(e.message)}</div>`;
        resultsDiv.classList.remove("hidden");
      } finally {
        setButtonLoading(importBtn, false);
      }
    };
  }

  async function renderAuditLogs() {
    const root = appRoot();
    root.innerHTML = "";
    const tb = topbar();
    root.appendChild(tb);

    tb.querySelector("#logoutBtn").onclick = async () => {
      const btn = tb.querySelector("#logoutBtn");
      setButtonLoading(btn, true, "Logout");
      try {
        await api("/api/auth/logout", { method:"POST", loadingKey: "logout" });
        state.me = null;
        toast("Logged out", { type: "success" });
        route();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(btn, false);
      }
    };
    tb.querySelector("#exportBtn").onclick = () => window.location.href = "/api/export/data";
    const iconLibraryBtn = tb.querySelector("#iconLibraryBtn");
    if (iconLibraryBtn) {
      iconLibraryBtn.onclick = () => openIconLibraryModal();
    }
    const manageUsersBtn = tb.querySelector("#manageUsersBtn");
    if (manageUsersBtn) {
      manageUsersBtn.onclick = () => openManageUsersModal();
    }
    const auditLogsBtn = tb.querySelector("#auditLogsBtn");
    if (auditLogsBtn) {
      auditLogsBtn.onclick = () => setRoute("#/audit-logs");
    }
    const settingsBtn = tb.querySelector("#settingsBtn");
    if (settingsBtn) {
      settingsBtn.onclick = () => showMfaSettingsModal();
    }
    tb.querySelector("#logoBtn").onclick = () => {
      setRoute("#/");
      route();
    };

    const content = el(`
      <div class="max-w-6xl mx-auto px-4 py-6">
        <div class="flex items-end justify-between gap-3 mb-6">
          <div>
            <div class="text-2xl font-semibold tracking-tight">Audit Logs</div>
            <div class="text-sm text-zinc-400">View all system activity and changes.</div>
          </div>
          <button id="backBtn" class="px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 text-sm text-zinc-200 hover:text-zinc-100 min-h-[44px] font-medium">← Back</button>
        </div>

        <div class="bg-zinc-900 border border-zinc-800 rounded-2xl p-4 mb-6">
          <div class="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div>
              <label class="text-xs text-zinc-400 mb-1 block">User</label>
              <input id="userFilter" type="text" placeholder="Filter by user..." class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 text-sm min-h-[44px]" />
            </div>
            <div>
              <label class="text-xs text-zinc-400 mb-1 block">Action</label>
              <input id="actionFilter" type="text" placeholder="Filter by action..." class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 text-sm min-h-[44px]" />
            </div>
            <div>
              <label class="text-xs text-zinc-400 mb-1 block">Date From</label>
              <input id="dateFrom" type="date" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 text-sm min-h-[44px]" />
            </div>
            <div>
              <label class="text-xs text-zinc-400 mb-1 block">Date To</label>
              <input id="dateTo" type="date" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 text-sm min-h-[44px]" />
            </div>
          </div>
          <div class="flex justify-end gap-2 mt-3">
            <button id="clearFiltersBtn" class="px-4 py-2 rounded-lg border border-zinc-800 hover:bg-zinc-950 text-sm font-medium min-h-[44px]">Clear Filters</button>
            <button id="applyFiltersBtn" class="px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm min-h-[44px]">Apply Filters</button>
          </div>
        </div>

        <div id="auditLogsContainer" class="space-y-3">
          <!-- Logs will be loaded here -->
        </div>
      </div>
    `);

    root.appendChild(content);
    content.querySelector("#backBtn").onclick = () => setRoute("#/");

    let currentFilters = {
      user: null,
      action: null,
      dateFrom: null,
      dateTo: null
    };

    async function loadAuditLogs() {
      const container = content.querySelector("#auditLogsContainer");
      container.innerHTML = '<div class="text-center py-8">' + spinner("w-6 h-6").outerHTML + '<div class="mt-2 text-zinc-400">Loading audit logs...</div></div>';

      try {
        const params = new URLSearchParams();
        if (currentFilters.user) params.append("user_filter", currentFilters.user);
        if (currentFilters.action) params.append("action_filter", currentFilters.action);
        if (currentFilters.dateFrom) {
          // Convert local date to UTC ISO string
          const date = new Date(currentFilters.dateFrom + "T00:00:00");
          params.append("date_from", date.toISOString());
        }
        if (currentFilters.dateTo) {
          // Convert local date to UTC ISO string (end of day)
          const date = new Date(currentFilters.dateTo + "T23:59:59");
          params.append("date_to", date.toISOString());
        }

        const res = await api(`/api/audit-logs?${params.toString()}`, { loadingKey: "audit-logs" });
        renderAuditLogEntries(container, res.entries || []);
      } catch (e) {
        container.innerHTML = `<div class="text-center py-8 text-red-400">Failed to load audit logs: ${escapeHtml(e.message)}</div>`;
        toast(e.message, { type: "error" });
      }
    }

    function renderAuditLogEntries(container, entries) {
      container.innerHTML = "";
      
      if (entries.length === 0) {
        container.appendChild(el(`<div class="text-center py-8 text-zinc-500">No audit log entries found.</div>`));
        return;
      }

      for (const entry of entries) {
        const card = el(`
          <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4 hover:bg-zinc-900/70 transition">
            <div class="flex items-start justify-between gap-3 mb-3">
              <div class="flex-1">
                <div class="flex items-center gap-2 mb-1">
                  <span class="text-sm font-medium text-zinc-200">${escapeHtml(entry.user || "unknown")}</span>
                  <span class="text-xs text-zinc-500">•</span>
                  <span class="text-xs text-zinc-400">${escapeHtml(entry.action || "")}</span>
                  <span class="text-xs text-zinc-500">•</span>
                  <span class="text-xs text-zinc-400">${escapeHtml(entry.entity || "")}</span>
                </div>
                <div class="text-xs text-zinc-500">${escapeHtml(entry.ts || "")}</div>
              </div>
              ${(entry.before || entry.after) ? `<button class="text-xs px-3 py-1.5 rounded-md border border-zinc-800 hover:bg-zinc-950 min-h-[32px] font-medium" data-show-diff>Show Changes</button>` : ''}
            </div>
            ${entry.before || entry.after ? `
              <div class="mt-3 pt-3 border-t border-zinc-800 hidden" data-diff-view>
                ${renderDiffView(entry.before, entry.after)}
              </div>
            ` : ''}
          </div>
        `);

        const showDiffBtn = card.querySelector("[data-show-diff]");
        if (showDiffBtn) {
          const diffView = card.querySelector("[data-diff-view]");
          showDiffBtn.onclick = () => {
            if (diffView.classList.contains("hidden")) {
              diffView.classList.remove("hidden");
              showDiffBtn.textContent = "Hide Changes";
            } else {
              diffView.classList.add("hidden");
              showDiffBtn.textContent = "Show Changes";
            }
          };
        }

        container.appendChild(card);
      }
    }

    function renderDiffView(before, after) {
      if (!before && !after) return "";
      
      const beforeStr = before ? JSON.stringify(before, null, 2) : "";
      const afterStr = after ? JSON.stringify(after, null, 2) : "";
      
      if (!before) {
        return `
          <div class="space-y-2">
            <div class="text-xs font-medium text-green-400">Added:</div>
            <pre class="text-xs bg-green-950/30 border border-green-800/50 rounded p-3 overflow-x-auto text-green-200">${escapeHtml(afterStr)}</pre>
          </div>
        `;
      }
      
      if (!after) {
        return `
          <div class="space-y-2">
            <div class="text-xs font-medium text-red-400">Removed:</div>
            <pre class="text-xs bg-red-950/30 border border-red-800/50 rounded p-3 overflow-x-auto text-red-200">${escapeHtml(beforeStr)}</pre>
          </div>
        `;
      }

      // Simple diff: show before and after side by side
      return `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div class="space-y-2">
            <div class="text-xs font-medium text-red-400">Before:</div>
            <pre class="text-xs bg-red-950/30 border border-red-800/50 rounded p-3 overflow-x-auto text-red-200 max-h-64 overflow-y-auto">${escapeHtml(beforeStr)}</pre>
          </div>
          <div class="space-y-2">
            <div class="text-xs font-medium text-green-400">After:</div>
            <pre class="text-xs bg-green-950/30 border border-green-800/50 rounded p-3 overflow-x-auto text-green-200 max-h-64 overflow-y-auto">${escapeHtml(afterStr)}</pre>
          </div>
        </div>
      `;
    }

    content.querySelector("#applyFiltersBtn").onclick = () => {
      currentFilters.user = content.querySelector("#userFilter").value.trim() || null;
      currentFilters.action = content.querySelector("#actionFilter").value.trim() || null;
      currentFilters.dateFrom = content.querySelector("#dateFrom").value || null;
      currentFilters.dateTo = content.querySelector("#dateTo").value || null;
      loadAuditLogs();
    };

    content.querySelector("#clearFiltersBtn").onclick = () => {
      content.querySelector("#userFilter").value = "";
      content.querySelector("#actionFilter").value = "";
      content.querySelector("#dateFrom").value = "";
      content.querySelector("#dateTo").value = "";
      currentFilters = { user: null, action: null, dateFrom: null, dateTo: null };
      loadAuditLogs();
    };

    // Load initial logs
    loadAuditLogs();
  }
  
  init();
  