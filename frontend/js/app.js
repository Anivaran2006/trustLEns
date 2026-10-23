/**
 * TrustLens AI — Frontend Client Logic
 * Handles interactive tabs, ML message analysis, AI investigation rendering,
 * audit ledger history, real-time KPI metrics, and user feedback.
 */

(function () {
  'use strict';

  // API Base Configuration
  const API_BASE = '/api/v1';

  // State
  let currentScanId = null;
  let sampleMessagesCache = [];
  let currentScannerMode = 'text'; // 'text' or 'multimodal'
  let selectedForensicFile = null;

  // Auth & Session State
  let currentUser = null;
  let csrfToken = null;
  let currentHistoryScope = 'guest'; // 'guest' or 'personal'

  // DOM Elements
  const elements = {
    // Nav & System Status
    systemStatusBadge: document.getElementById('systemStatusBadge'),
    systemStatusText: document.getElementById('systemStatusText'),
    modelVersionPill: document.getElementById('modelVersionPill'),
    navTabs: document.querySelectorAll('.nav-tab'),
    tabPanes: document.querySelectorAll('.tab-pane'),

    // Header Auth Controls
    btnHeaderBackHome: document.getElementById('btnHeaderBackHome'),
    btnHeaderSignIn: document.getElementById('btnHeaderSignIn'),
    btnHeaderRegister: document.getElementById('btnHeaderRegister'),
    headerGuestActions: document.getElementById('headerGuestActions'),
    headerUserMenu: document.getElementById('headerUserMenu'),
    userMenuToggleBtn: document.getElementById('userMenuToggleBtn'),
    userNameLabel: document.getElementById('userNameLabel'),
    userAvatarInitial: document.getElementById('userAvatarInitial'),
    userDropdownMenu: document.getElementById('userDropdownMenu'),
    dropdownUserName: document.getElementById('dropdownUserName'),
    dropdownUserEmail: document.getElementById('dropdownUserEmail'),
    dropdownItemAccount: document.getElementById('dropdownItemAccount'),
    dropdownItemMyScans: document.getElementById('dropdownItemMyScans'),
    dropdownItemLogout: document.getElementById('dropdownItemLogout'),
    btnReturnHome: document.getElementById('btnReturnHome'),
    mainNavTabsBar: document.getElementById('mainNavTabsBar'),

    // Auth Tab Elements (#authTab)
    tabBtnSignIn: document.getElementById('tabBtnSignIn'),
    tabBtnSignUp: document.getElementById('tabBtnSignUp'),
    authAlertBanner: document.getElementById('authAlertBanner'),
    authAlertText: document.getElementById('authAlertText'),
    formLogin: document.getElementById('formLogin'),
    loginEmail: document.getElementById('loginEmail'),
    loginPassword: document.getElementById('loginPassword'),
    toggleLoginPassword: document.getElementById('toggleLoginPassword'),
    btnLoginSubmit: document.getElementById('btnLoginSubmit'),
    loginBtnText: document.getElementById('loginBtnText'),
    loginSpinner: document.getElementById('loginSpinner'),
    linkSwitchToSignUp: document.getElementById('linkSwitchToSignUp'),

    formRegister: document.getElementById('formRegister'),
    regFullName: document.getElementById('regFullName'),
    regEmail: document.getElementById('regEmail'),
    regPassword: document.getElementById('regPassword'),
    toggleRegPassword: document.getElementById('toggleRegPassword'),
    regConfirmPassword: document.getElementById('regConfirmPassword'),
    toggleRegConfirmPassword: document.getElementById('toggleRegConfirmPassword'),
    btnRegisterSubmit: document.getElementById('btnRegisterSubmit'),
    regBtnText: document.getElementById('regBtnText'),
    regSpinner: document.getElementById('regSpinner'),
    linkSwitchToSignIn: document.getElementById('linkSwitchToSignIn'),
    btnContinueGuest: document.getElementById('btnContinueGuest'),

    // Account Tab Elements (#accountTab)
    accountAvatarLarge: document.getElementById('accountAvatarLarge'),
    accountProfileName: document.getElementById('accountProfileName'),
    accountProfileEmail: document.getElementById('accountProfileEmail'),
    accountScanCount: document.getElementById('accountScanCount'),
    accountMemberSince: document.getElementById('accountMemberSince'),
    btnAccountViewScans: document.getElementById('btnAccountViewScans'),
    btnAccountNewScan: document.getElementById('btnAccountNewScan'),
    btnAccountLogout: document.getElementById('btnAccountLogout'),

    // History Scope Switcher
    btnScopeGuest: document.getElementById('btnScopeGuest'),
    btnScopePersonal: document.getElementById('btnScopePersonal'),

    // Scanner Mode Switch & Views
    btnModeText: document.getElementById('btnModeText'),
    btnModeMultimodal: document.getElementById('btnModeMultimodal'),
    textInputView: document.getElementById('textInputView'),
    multimodalInputView: document.getElementById('multimodalInputView'),
    textQuickSampleWrapper: document.getElementById('textQuickSampleWrapper'),

    // Text Scanner Elements
    messageInput: document.getElementById('messageInput'),
    charCounter: document.getElementById('charCounter'),
    btnPasteClipboard: document.getElementById('btnPasteClipboard'),
    btnClearInput: document.getElementById('btnClearInput'),
    btnAnalyze: document.getElementById('btnAnalyze'),
    analyzeSpinner: document.getElementById('analyzeSpinner'),
    analyzeBtnText: document.getElementById('analyzeBtnText'),
    quickSampleSelect: document.getElementById('quickSampleSelect'),

    // Multi-Modal Forensic Elements
    dropZone: document.getElementById('dropZone'),
    fileInput: document.getElementById('fileInput'),
    filePreviewBox: document.getElementById('filePreviewBox'),
    filePreviewThumb: document.getElementById('filePreviewThumb'),
    pdfIconPlaceholder: document.getElementById('pdfIconPlaceholder'),
    filePreviewName: document.getElementById('filePreviewName'),
    filePreviewSize: document.getElementById('filePreviewSize'),
    filePreviewType: document.getElementById('filePreviewType'),
    btnRemoveFile: document.getElementById('btnRemoveFile'),
    mediaNoteInput: document.getElementById('mediaNoteInput'),
    btnSampleQuishing: document.getElementById('btnSampleQuishing'),
    btnSampleInvoice: document.getElementById('btnSampleInvoice'),

    // Multimodal Forensic Results Card Elements
    multimodalForensicCard: document.getElementById('multimodalForensicCard'),
    multimodalClassificationBadge: document.getElementById('multimodalClassificationBadge'),
    qrForensicRow: document.getElementById('qrForensicRow'),
    qrRiskLabel: document.getElementById('qrRiskLabel'),
    qrPayloadCode: document.getElementById('qrPayloadCode'),
    qrDomainText: document.getElementById('qrDomainText'),
    brandsRow: document.getElementById('brandsRow'),
    detectedBrandsList: document.getElementById('detectedBrandsList'),
    docTextRow: document.getElementById('docTextRow'),
    docTextSnippet: document.getElementById('docTextSnippet'),

    // Results
    preScanGuidanceCard: document.getElementById('preScanGuidanceCard'),
    resultsPlaceholder: document.getElementById('resultsPlaceholder'),
    resultsCard: document.getElementById('resultsCard'),
    riskBadge: document.getElementById('riskBadge'),
    classificationTag: document.getElementById('classificationTag'),
    scoreValue: document.getElementById('scoreValue'),
    riskMeterFill: document.getElementById('riskMeterFill'),
    investigationSummary: document.getElementById('investigationSummary'),
    investigationProvider: document.getElementById('investigationProvider'),
    observableSignsList: document.getElementById('observableSignsList'),
    directObservationsList: document.getElementById('directObservationsList'),
    potentialImplicationsList: document.getElementById('potentialImplicationsList'),
    recommendedActionsList: document.getElementById('recommendedActionsList'),
    uncertaintyText: document.getElementById('uncertaintyText'),
    btnFeedbackHelpful: document.getElementById('btnFeedbackHelpful'),
    btnFeedbackIncorrect: document.getElementById('btnFeedbackIncorrect'),
    feedbackStatusMsg: document.getElementById('feedbackStatusMsg'),

    // Dashboard
    kpiTotalScans: document.getElementById('kpiTotalScans'),
    kpiSuspiciousScans: document.getElementById('kpiSuspiciousScans'),
    kpiSuspiciousRate: document.getElementById('kpiSuspiciousRate'),
    kpiLegitScans: document.getElementById('kpiLegitScans'),
    kpiLegitRate: document.getElementById('kpiLegitRate'),
    kpiAvgRisk: document.getElementById('kpiAvgRisk'),
    btnRefreshDashboard: document.getElementById('btnRefreshDashboard'),
    barLow: document.getElementById('barLow'),
    barMedium: document.getElementById('barMedium'),
    barHigh: document.getElementById('barHigh'),
    countLow: document.getElementById('countLow'),
    countMedium: document.getElementById('countMedium'),
    countHigh: document.getElementById('countHigh'),
    dashboardRecentTbody: document.getElementById('dashboardRecentTbody'),

    // History
    historyRiskFilter: document.getElementById('historyRiskFilter'),
    historySearchInput: document.getElementById('historySearchInput'),
    btnApplyHistoryFilter: document.getElementById('btnApplyHistoryFilter'),
    btnResetHistoryFilter: document.getElementById('btnResetHistoryFilter'),
    btnClearAllHistory: document.getElementById('btnClearAllHistory'),
    historyTbody: document.getElementById('historyTbody'),
    historyRecordCount: document.getElementById('historyRecordCount'),

    // Samples
    samplesGallery: document.getElementById('samplesGallery'),

    // Modal
    detailModal: document.getElementById('detailModal'),
    modalTitle: document.getElementById('modalTitle'),
    modalBodyContent: document.getElementById('modalBodyContent'),
    btnCloseModal: document.getElementById('btnCloseModal'),
    btnModalDismiss: document.getElementById('btnModalDismiss'),

    // Toast
    toastContainer: document.getElementById('toastContainer'),

    // AI Copilot Elements
    copilotPanel: document.getElementById('copilotPanel'),
    copilotProviderPill: document.getElementById('copilotProviderPill'),
    copilotProgressBox: document.getElementById('copilotProgressBox'),
    progressTimeElapsed: document.getElementById('progressTimeElapsed'),
    stepSanitize: document.getElementById('stepSanitize'),
    statusStep1: document.getElementById('statusStep1'),
    stepInference: document.getElementById('stepInference'),
    statusStep2: document.getElementById('statusStep2'),
    stepIndicators: document.getElementById('stepIndicators'),
    statusStep3: document.getElementById('statusStep3'),
    stepSynthesis: document.getElementById('stepSynthesis'),
    statusStep4: document.getElementById('statusStep4'),
    copilotChatFeed: document.getElementById('copilotChatFeed'),
    copilotSuggestionsList: document.getElementById('copilotSuggestionsList'),
    copilotQueryInput: document.getElementById('copilotQueryInput'),
    btnSendCopilotQuery: document.getElementById('btnSendCopilotQuery'),

    // Alexa+ Simulated Experience Elements
    tabBtnAlexaSim: document.getElementById('tabBtnAlexaSim'),
    btnHeaderAlexa: document.getElementById('btnHeaderAlexa'),
    heroBtnAlexa: document.getElementById('heroBtnAlexa'),
    heroHackathonBadge: document.getElementById('heroHackathonBadge'),
    alexaSimTab: document.getElementById('alexaSimTab'),
    alexaChatFeed: document.getElementById('alexaChatFeed'),
    alexaQueryInput: document.getElementById('alexaQueryInput'),
    btnSendAlexaQuery: document.getElementById('btnSendAlexaQuery'),
    btnResetAlexaChat: document.getElementById('btnResetAlexaChat'),
    alexaThinkingIndicator: document.getElementById('alexaThinkingIndicator'),
    alexaPresetsGrid: document.getElementById('alexaPresetsGrid'),
    btnViewMcpTools: document.getElementById('btnViewMcpTools'),
    modalMcpTools: document.getElementById('modalMcpTools'),
    btnCloseMcpModal: document.getElementById('btnCloseMcpModal'),
    btnDismissMcpModal: document.getElementById('btnDismissMcpModal'),
    mcpToolsCodeBlock: document.getElementById('mcpToolsCodeBlock'),
    alexaProviderTag: document.getElementById('alexaProviderTag'),
    alexaInputCharCount: document.getElementById('alexaInputCharCount')
  };

  // --- Initializer ---
  document.addEventListener('DOMContentLoaded', async () => {
    initNavigation();
    initLandingPage();
    initDashboard();
    initScanner();
    initPreScanGuidance();
    initCopilot();
    initAlexaSimulator();
    initHistory();
    initFeedback();
    initModal();
    initAuth();
    await checkAuthStatus();
    checkSystemReadiness();
    loadSampleMessages();
    handleInitialRouting();
  });

  // --- System Readiness & Liveness ---
  async function checkSystemReadiness() {
    const dashStatusDot = document.getElementById('dashStatusDot');
    const dashStatusText = document.getElementById('dashStatusText');

    try {
      const resp = await fetch('/ready');
      if (!resp.ok) throw new Error('Ready endpoint returned non-200');
      const data = await resp.json();

      if (data.status === 'ready') {
        elements.systemStatusBadge.className = 'status-pill status-ready';
        elements.systemStatusText.textContent = 'System Active';
        elements.systemStatusBadge.title = `Model loaded. DB connected. AI: ${data.llm_provider}`;
        if (dashStatusDot) dashStatusDot.className = 'status-dot status-ready';
        if (dashStatusText) dashStatusText.textContent = 'Inference Engine Operational';
      } else {
        elements.systemStatusBadge.className = 'status-pill status-error';
        elements.systemStatusText.textContent = 'Not Ready';
        if (dashStatusDot) dashStatusDot.className = 'status-dot status-error';
        if (dashStatusText) dashStatusText.textContent = 'Engine Offline / Error';
      }

      if (elements.copilotProviderPill) {
        elements.copilotProviderPill.textContent = data.llm_provider && data.llm_provider.includes('Bedrock')
          ? 'Bedrock AI'
          : 'Rule-Based NLP';
      }

      if (elements.alexaProviderTag && data.llm_provider) {
        elements.alexaProviderTag.textContent = `NLP Engine: ${data.llm_provider}`;
      }

      if (data.model_version && data.selected_model) {
        elements.modelVersionPill.textContent = `${data.selected_model} (v${data.model_version})`;
      }
    } catch (err) {
      elements.systemStatusBadge.className = 'status-pill status-error';
      elements.systemStatusText.textContent = 'Offline / Error';
      if (dashStatusDot) dashStatusDot.className = 'status-dot status-error';
      if (dashStatusText) dashStatusText.textContent = 'Engine Offline / Error';
    }
  }

  // --- Navigation & Client-Side Routing ---
  const ROUTE_MAP = {
    'landingTab': 'home',
    'alexaSimTab': 'alexa',
    'scannerTab': 'scanner',
    'dashboardTab': 'dashboard',
    'historyTab': 'history',
    'samplesTab': 'samples',
    'architectureTab': 'model',
    'authTab': 'login',
    'accountTab': 'account'
  };

  const REVERSE_ROUTE_MAP = {
    'home': 'landingTab',
    'landing': 'landingTab',
    'landingtab': 'landingTab',
    'alexa': 'alexaSimTab',
    'alexasim': 'alexaSimTab',
    'alexasimtab': 'alexaSimTab',
    'alexa-sim': 'alexaSimTab',
    'alexa-experience': 'alexaSimTab',
    'scanner': 'scannerTab',
    'scannertab': 'scannerTab',
    'dashboard': 'dashboardTab',
    'dashboardtab': 'dashboardTab',
    'history': 'historyTab',
    'historytab': 'historyTab',
    'samples': 'samplesTab',
    'samplestab': 'samplesTab',
    'model': 'architectureTab',
    'architecture': 'architectureTab',
    'architecturetab': 'architectureTab',
    'login': 'authTab',
    'signin': 'authTab',
    'signup': 'authTab',
    'register': 'authTab',
    'auth': 'authTab',
    'authtab': 'authTab',
    'account': 'accountTab',
    'profile': 'accountTab',
    'accounttab': 'accountTab'
  };

  const PROTECTED_TABS = ['scannerTab', 'dashboardTab', 'historyTab', 'samplesTab', 'architectureTab', 'accountTab'];
  const VALID_RETURN_ROUTES = ['scanner', 'dashboard', 'history', 'samples', 'model', 'account'];
  let authReturnDestination = null;

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function getRouteFromLocation() {
    const fullHash = (window.location.hash || '').replace(/^#\/?/, '').trim();
    const hashParts = fullHash.split('?');
    const rawHash = (hashParts[0] || '').toLowerCase();

    // Check for return_to parameter in hash or query string
    const urlParams = new URLSearchParams(hashParts[1] || window.location.search);
    const returnTo = urlParams.get('return_to');
    if (returnTo && VALID_RETURN_ROUTES.includes(returnTo.toLowerCase())) {
      authReturnDestination = returnTo.toLowerCase();
    }

    const rawPath = (window.location.pathname || '').replace(/^\/+/, '').trim().toLowerCase();

    if (rawHash && REVERSE_ROUTE_MAP[rawHash]) {
      return REVERSE_ROUTE_MAP[rawHash];
    }
    if (rawPath && REVERSE_ROUTE_MAP[rawPath]) {
      return REVERSE_ROUTE_MAP[rawPath];
    }
    return 'landingTab';
  }

  function navigateTo(target, updateHistory = true) {
    if (!target) return;
    const cleanTarget = target.toLowerCase();
    const tabId = REVERSE_ROUTE_MAP[cleanTarget] || target;
    const routeSlug = ROUTE_MAP[tabId] || 'home';

    // Strict Access Control: if route is protected and user is not authenticated, redirect to login with safe return_to
    if (PROTECTED_TABS.includes(tabId) && !currentUser) {
      authReturnDestination = routeSlug;
      showToast('Please sign in to access your security workspace.', 'info');
      navigateTo('login', updateHistory);
      return;
    }

    // If user is already authenticated and visits login/register, redirect to their workspace or intended destination
    if (tabId === 'authTab' && currentUser) {
      const dest = authReturnDestination && VALID_RETURN_ROUTES.includes(authReturnDestination)
        ? authReturnDestination
        : 'scanner';
      authReturnDestination = null;
      navigateTo(dest, updateHistory);
      return;
    }

    // Toggle minimal header mode on auth page
    if (tabId === 'authTab') {
      document.body.classList.add('auth-page-mode');
      if (elements.headerGuestActions) elements.headerGuestActions.style.display = 'none';
      if (elements.btnHeaderBackHome) elements.btnHeaderBackHome.style.display = 'inline-flex';
      if (cleanTarget === 'register' || cleanTarget === 'signup') {
        switchAuthMode('register');
      } else {
        switchAuthMode('login');
      }
    } else {
      document.body.classList.remove('auth-page-mode');
      if (elements.btnHeaderBackHome) elements.btnHeaderBackHome.style.display = 'none';
      if (!currentUser && elements.headerGuestActions) {
        elements.headerGuestActions.style.display = 'inline-flex';
      }
    }

    // 1. Highlight active navigation tab
    elements.navTabs.forEach(t => {
      const match = t.getAttribute('data-tab') === tabId || t.getAttribute('data-route') === routeSlug;
      t.classList.toggle('active', match);
      t.setAttribute('aria-selected', match ? 'true' : 'false');
    });

    // 2. Strict view isolation: hide all non-selected tabs, show only selected tab
    elements.tabPanes.forEach(pane => {
      const isTarget = pane.id === tabId;
      pane.classList.toggle('active', isTarget);
      pane.classList.toggle('hidden', !isTarget);
    });

    // 3. Update browser history if requested (pushState for browser back/forward support)
    if (updateHistory && window.history && window.history.pushState) {
      let newHash = '#' + (cleanTarget === 'register' ? 'register' : routeSlug);
      if (tabId === 'authTab' && authReturnDestination && !currentUser) {
        newHash += `?return_to=${encodeURIComponent(authReturnDestination)}`;
      }
      if (window.location.hash !== newHash) {
        window.history.pushState({ tabId, routeSlug }, '', newHash);
      }
    }

    // 4. Scroll to top instantly
    window.scrollTo({ top: 0, behavior: 'instant' });

    // 5. Context-dependent data fetching
    if (tabId === 'dashboardTab' && currentUser) {
      loadDashboardMetrics();
    } else if (tabId === 'historyTab' && currentUser) {
      loadScanHistory();
    } else if (tabId === 'accountTab' && currentUser) {
      renderAccountDashboard();
    }
  }

  function switchTab(tabId) {
    navigateTo(tabId, true);
  }

  function initNavigation() {
    // Nav bar tab buttons
    elements.navTabs.forEach(tab => {
      tab.addEventListener('click', (e) => {
        e.preventDefault();
        const target = tab.getAttribute('data-route') || tab.getAttribute('data-tab');
        navigateTo(target, true);
      });
    });

    // Browser back/forward navigation support
    window.addEventListener('popstate', () => {
      const destination = getRouteFromLocation();
      navigateTo(destination, false);
    });

    // URL hashchange support
    window.addEventListener('hashchange', () => {
      const destination = getRouteFromLocation();
      navigateTo(destination, false);
    });
  }

  function handleInitialRouting() {
    const destination = getRouteFromLocation();
    navigateTo(destination, false);
  }

  // 1-Click Fast-Test Scenarios in #preScanGuidanceCard
  const PRESET_SCENARIOS = {
    bank: "URGENT: Chase Bank Alert. Your debit card has been suspended due to unusual activity. Verify your identity immediately to restore access: http://chase-secure-verify.com/login",
    delivery: "USPS Notification: Your package delivery has an unpaid fee of $2.35. Avoid return to sender by settling today: https://usps-track-fee.org/pay",
    legit: "Your Microsoft security verification code is 849201. If you did not request this code, no action is needed. Do not share this code with anyone."
  };

  function initPreScanGuidance() {
    const guidanceCard = document.getElementById('preScanGuidanceCard');
    if (!guidanceCard) return;

    guidanceCard.addEventListener('click', (e) => {
      const scenarioEl = e.target.closest('[data-scenario]');
      if (!scenarioEl) return;

      const scenarioKey = scenarioEl.getAttribute('data-scenario');
      const text = PRESET_SCENARIOS[scenarioKey];
      if (!text) return;

      if (currentScannerMode !== 'text') {
        setScannerMode('text');
      }

      if (elements.messageInput) {
        elements.messageInput.value = text;
        elements.messageInput.dispatchEvent(new Event('input'));
        elements.messageInput.focus();
      }

      showToast(`Loaded ${scenarioKey.toUpperCase()} threat vector. Running forensic scan...`, 'info');
      handleAnalyze();
    });
  }

  // --- Landing Page Interactive Elements & Scroll Animations ---
  function initLandingPage() {
    // 1. Header & Hero CTAs
    const btnHeaderScanner = document.getElementById('btnHeaderScanner');
    if (btnHeaderScanner) {
      btnHeaderScanner.addEventListener('click', () => {
        switchTab('scannerTab');
        if (elements.messageInput) elements.messageInput.focus();
      });
    }

    const heroBtnScanner = document.getElementById('heroBtnScanner');
    if (heroBtnScanner) {
      heroBtnScanner.addEventListener('click', () => {
        switchTab('scannerTab');
        if (elements.messageInput) elements.messageInput.focus();
      });
    }

    const heroBtnSamples = document.getElementById('heroBtnSamples');
    if (heroBtnSamples) {
      heroBtnSamples.addEventListener('click', () => switchTab('samplesTab'));
    }

    const heroBtnHowItWorks = document.getElementById('heroBtnHowItWorks');
    if (heroBtnHowItWorks) {
      heroBtnHowItWorks.addEventListener('click', (e) => {
        e.preventDefault();
        const section = document.getElementById('howItWorksSection');
        if (section) section.scrollIntoView({ behavior: 'smooth' });
      });
    }

    // 2. Final CTA Banner
    const finalBtnScanner = document.getElementById('finalBtnScanner');
    if (finalBtnScanner) {
      finalBtnScanner.addEventListener('click', () => {
        switchTab('scannerTab');
        if (elements.messageInput) elements.messageInput.focus();
      });
    }

    const finalBtnDashboard = document.getElementById('finalBtnDashboard');
    if (finalBtnDashboard) {
      finalBtnDashboard.addEventListener('click', () => switchTab('dashboardTab'));
    }

    const finalBtnModelCard = document.getElementById('finalBtnModelCard');
    if (finalBtnModelCard) {
      finalBtnModelCard.addEventListener('click', () => switchTab('architectureTab'));
    }

    // 3. Footer Links
    document.querySelectorAll('.footer-link-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-target');
        if (target) switchTab(target);
      });
    });

    // 4. Interactive Demonstration Switcher
    const DEMO_PREVIEWS = {
      bank: {
        text: "URGENT: Chase Bank Alert. Your debit card has been suspended due to unusual activity. Verify your identity immediately to restore access: http://chase-secure-verify.com/login",
        badgeText: "HIGH RISK",
        badgeClass: "risk-high",
        prob: "94% Suspicious",
        arch: "Logistic Regression (TF-IDF 1-2g)",
        indicators: [
          "Suspicious Domain: chase-secure-verify.com",
          "Cognitive Urgency: suspended",
          "Credential Harvester Lure"
        ],
        summary: "Impersonates Chase financial institution using urgency cues and an unverified external domain to harvest banking credentials."
      },
      usps: {
        text: "USPS Notice: Your parcel package #US982420 cannot be delivered due to an unpaid postage fee of $2.49. Please update your details within 24 hours at http://usps-redelivery-portal.xyz/pay",
        badgeText: "HIGH RISK",
        badgeClass: "risk-high",
        prob: "91% Suspicious",
        arch: "Logistic Regression (TF-IDF 1-2g)",
        indicators: [
          "Suspicious TLD: .xyz",
          "Financial Demand: $2.49 postage",
          "Postal Smishing Redirection"
        ],
        summary: "Exploits USPS brand name with an unexpected fee demand to coerce credit card submission on an unauthorized third-party portal."
      },
      clean: {
        text: "Your Google verification code is 482910. Do not share this code with anyone.",
        badgeText: "LOW RISK",
        badgeClass: "risk-low",
        prob: "4% Suspicious",
        arch: "Logistic Regression (TF-IDF 1-2g)",
        indicators: [
          "Standard 2FA Authentication Pattern",
          "No Embedded External URLs",
          "Zero Sensitive Credential Requests"
        ],
        summary: "Transactional two-factor authentication notice with standard advisory text. No anomalous deception cues detected."
      }
    };

    const demoTabs = document.querySelectorAll('.demo-tab');
    const demoSampleText = document.getElementById('demoSampleText');
    const demoRiskBadge = document.getElementById('demoRiskBadge');
    const demoScoreVal = document.getElementById('demoScoreVal');
    const demoIndicatorsList = document.getElementById('demoIndicatorsList');
    const demoAiSummary = document.getElementById('demoAiSummary');

    demoTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        demoTabs.forEach(t => {
          const isCurrent = t === tab;
          t.classList.toggle('active', isCurrent);
          t.setAttribute('aria-selected', isCurrent ? 'true' : 'false');
        });

        const sampleKey = tab.getAttribute('data-sample') || 'bank';
        const sample = DEMO_PREVIEWS[sampleKey] || DEMO_PREVIEWS.bank;

        if (demoSampleText) demoSampleText.textContent = sample.text;
        if (demoRiskBadge) {
          demoRiskBadge.textContent = sample.badgeText;
          demoRiskBadge.className = `risk-badge ${sample.badgeClass}`;
        }
        if (demoScoreVal) demoScoreVal.textContent = sample.prob;
        if (demoIndicatorsList) {
          demoIndicatorsList.innerHTML = sample.indicators
            .map(ind => `<span class="indicator-tag">${escapeHtml(ind)}</span>`)
            .join('');
        }
        if (demoAiSummary) {
          demoAiSummary.innerHTML = `<strong>AI Copilot Assessment:</strong> ${escapeHtml(sample.summary)}`;
        }
      });
    });

    // 5. "Analyze in Full Scanner Console" Button
    const btnLaunchInScanner = document.getElementById('btnLaunchInScanner');
    if (btnLaunchInScanner) {
      btnLaunchInScanner.addEventListener('click', () => {
        const activeTab = document.querySelector('.demo-tab.active');
        const sampleKey = activeTab ? activeTab.getAttribute('data-sample') : 'bank';
        const sample = DEMO_PREVIEWS[sampleKey] || DEMO_PREVIEWS.bank;

        setScannerMode('text');
        if (elements.messageInput) {
          elements.messageInput.value = sample.text;
          elements.messageInput.dispatchEvent(new Event('input'));
        }
        switchTab('scannerTab');
        showToast('Sample loaded into Scanner. Click "Run Investigation" to execute full pipeline.', 'info');
        if (elements.messageInput) elements.messageInput.focus();
      });
    }

    // 6. Scroll Reveal Observer
    if ('IntersectionObserver' in window) {
      const scrollObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            entry.target.classList.add('revealed');
            scrollObserver.unobserve(entry.target);
          }
        });
      }, { threshold: 0.1 });

      document.querySelectorAll('.reveal-on-scroll').forEach(el => scrollObserver.observe(el));
    } else {
      document.querySelectorAll('.reveal-on-scroll').forEach(el => el.classList.add('revealed'));
    }
  }

  // --- Toast Notifications ---
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    elements.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  // --- Scanner Mode Switching ---
  function setScannerMode(mode) {
    currentScannerMode = mode;
    const isText = mode === 'text';

    elements.btnModeText.classList.toggle('active', isText);
    elements.btnModeMultimodal.classList.toggle('active', !isText);

    elements.textInputView.classList.toggle('hidden', !isText);
    elements.multimodalInputView.classList.toggle('hidden', isText);

    if (elements.textQuickSampleWrapper) {
      elements.textQuickSampleWrapper.classList.toggle('hidden', !isText);
    }

    elements.analyzeBtnText.textContent = isText ? 'Analyze Message' : 'Run Multi-Modal Forensics';
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function handleFileSelected(file) {
    if (!file) return;

    if (file.size > 10 * 1024 * 1024) {
      showToast('File exceeds 10MB limit. Please select a smaller file.', 'error');
      return;
    }

    selectedForensicFile = file;
    elements.filePreviewBox.classList.remove('hidden');
    elements.filePreviewName.textContent = file.name;
    elements.filePreviewSize.textContent = formatBytes(file.size);

    const isPdf = file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf');
    elements.filePreviewType.textContent = isPdf ? 'PDF Document' : 'Visual Image Artifact';

    if (isPdf) {
      elements.filePreviewThumb.classList.add('hidden');
      elements.pdfIconPlaceholder.classList.remove('hidden');
    } else {
      elements.pdfIconPlaceholder.classList.add('hidden');
      elements.filePreviewThumb.classList.remove('hidden');
      const reader = new FileReader();
      reader.onload = (e) => {
        elements.filePreviewThumb.src = e.target.result;
      };
      reader.readAsDataURL(file);
    }

    showToast(`Artifact staged: ${file.name}`, 'info');
  }

  function clearSelectedFile() {
    selectedForensicFile = null;
    elements.filePreviewBox.classList.add('hidden');
    elements.filePreviewThumb.src = '';
    elements.fileInput.value = '';
  }

  async function loadSampleFile(url, filename, mimeType) {
    try {
      setScannerMode('multimodal');
      showToast(`Loading demo sample ${filename}...`, 'info');
      const response = await fetch(url);
      if (!response.ok) throw new Error('Sample asset not found on server.');
      const blob = await response.blob();
      const file = new File([blob], filename, { type: mimeType });
      handleFileSelected(file);
    } catch (err) {
      showToast(`Failed to load sample: ${err.message}`, 'error');
    }
  }

  // --- Scanner Logic ---
  function initScanner() {
    // Mode Switch buttons
    elements.btnModeText.addEventListener('click', () => setScannerMode('text'));
    elements.btnModeMultimodal.addEventListener('click', () => setScannerMode('multimodal'));

    // Character counter
    elements.messageInput.addEventListener('input', () => {
      const len = elements.messageInput.value.length;
      elements.charCounter.textContent = `${len.toLocaleString()} / 5,000 characters`;
    });

    // Paste from clipboard (Text mode)
    elements.btnPasteClipboard.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          elements.messageInput.value = text;
          elements.messageInput.dispatchEvent(new Event('input'));
          showToast('Pasted content from clipboard.', 'success');
        }
      } catch (err) {
        showToast('Clipboard access restricted. Please paste using Ctrl+V.', 'error');
      }
    });

    // Clear input
    elements.btnClearInput.addEventListener('click', () => {
      elements.messageInput.value = '';
      elements.messageInput.dispatchEvent(new Event('input'));
      elements.resultsCard.classList.add('hidden');
      if (elements.preScanGuidanceCard) elements.preScanGuidanceCard.classList.remove('hidden');
      elements.messageInput.focus();
    });

    // Dropzone Click & Drag events
    elements.dropZone.addEventListener('click', () => elements.fileInput.click());
    elements.dropZone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        elements.fileInput.click();
      }
    });

    elements.fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleFileSelected(e.target.files[0]);
      }
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      elements.dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        elements.dropZone.classList.add('drag-over');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      elements.dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        elements.dropZone.classList.remove('drag-over');
      });
    });

    elements.dropZone.addEventListener('drop', (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleFileSelected(e.dataTransfer.files[0]);
      }
    });

    // Remove file button
    elements.btnRemoveFile.addEventListener('click', clearSelectedFile);

    // 1-Click Forensic Demo Sample Chips
    elements.btnSampleQuishing.addEventListener('click', () => {
      loadSampleFile('/static/samples/sample_quishing_scam.png', 'sample_quishing_scam.png', 'image/png');
    });

    elements.btnSampleInvoice.addEventListener('click', () => {
      loadSampleFile('/static/samples/sample_amazon_fake_invoice.png', 'sample_amazon_fake_invoice.png', 'image/png');
    });

    // Global Paste Listener (Ctrl+V captures screenshots)
    window.addEventListener('paste', (e) => {
      const items = (e.clipboardData || e.originalEvent.clipboardData).items;
      for (const item of items) {
        if (item.kind === 'file' && item.type.startsWith('image/')) {
          const blob = item.getAsFile();
          const pasteFile = new File([blob], `screenshot_${Date.now()}.png`, { type: item.type });
          setScannerMode('multimodal');
          handleFileSelected(pasteFile);
          showToast('Screenshot pasted from clipboard into Multi-Modal Forensics!', 'success');
          break;
        }
      }
    });

    // Quick sample dropdown select
    elements.quickSampleSelect.addEventListener('change', (e) => {
      const sampleId = e.target.value;
      if (!sampleId) return;
      const found = sampleMessagesCache.find(s => s.id === sampleId);
      if (found) {
        elements.messageInput.value = found.text;
        elements.messageInput.dispatchEvent(new Event('input'));
      }
    });

    // Analyze Button
    elements.btnAnalyze.addEventListener('click', handleAnalyze);
  }

  async function handleAnalyze() {
    if (currentScannerMode === 'multimodal') {
      if (!selectedForensicFile) {
        showToast('Please upload or paste an image/document or select a demo sample.', 'error');
        return;
      }

      setAnalyzingState(true);
      startInvestigationProgress();

      try {
        const formData = new FormData();
        formData.append('file', selectedForensicFile);
        const note = elements.mediaNoteInput.value.trim();
        if (note) formData.append('user_note', note);

        const headers = {};
        if (csrfToken) headers['X-CSRF-Token'] = csrfToken;

        const resp = await fetch(`${API_BASE}/analyze-multimodal`, {
          method: 'POST',
          headers,
          credentials: 'same-origin',
          body: formData
        });

        if (!resp.ok) {
          const errorData = await resp.json().catch(() => ({}));
          throw new Error(errorData.detail || `Server returned error (${resp.status})`);
        }

        const result = await resp.json();
        currentScanId = result.scan_id;
        finishInvestigationProgress(true);
        renderInvestigationResult(result);
        addCopilotBriefing(result);
        if (currentUser) checkAuthStatus();
        showToast('Multi-Modal forensic investigation complete.', 'success');
      } catch (err) {
        finishInvestigationProgress(false);
        showToast(`Forensic error: ${err.message}`, 'error');
      } finally {
        setAnalyzingState(false);
      }
      return;
    }

    // Standard Text Mode
    const message = elements.messageInput.value.trim();
    if (!message) {
      showToast('Please enter or paste a message to analyze.', 'error');
      elements.messageInput.focus();
      return;
    }

    setAnalyzingState(true);
    startInvestigationProgress();

    try {
      const headers = { 'Content-Type': 'application/json' };
      if (csrfToken) headers['X-CSRF-Token'] = csrfToken;

      const resp = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers,
        credentials: 'same-origin',
        body: JSON.stringify({ message: message })
      });

      if (!resp.ok) {
        const errorData = await resp.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server returned error (${resp.status})`);
      }

      const result = await resp.json();
      currentScanId = result.scan_id;
      finishInvestigationProgress(true);
      renderInvestigationResult(result);
      addCopilotBriefing(result);
      if (currentUser) checkAuthStatus();
      showToast('Investigation complete.', 'success');
    } catch (err) {
      finishInvestigationProgress(false);
      showToast(`Analysis error: ${err.message}`, 'error');
    } finally {
      setAnalyzingState(false);
    }
  }

  function setAnalyzingState(isAnalyzing) {
    elements.btnAnalyze.disabled = isAnalyzing;
    elements.analyzeSpinner.classList.toggle('hidden', !isAnalyzing);
    if (isAnalyzing && elements.preScanGuidanceCard) {
      elements.preScanGuidanceCard.classList.add('hidden');
    }
    if (currentScannerMode === 'multimodal') {
      elements.analyzeBtnText.textContent = isAnalyzing ? 'Scanning Artifact...' : 'Run Multi-Modal Forensics';
    } else {
      elements.analyzeBtnText.textContent = isAnalyzing ? 'Investigating...' : 'Analyze Message';
    }
  }

  function renderInvestigationResult(data) {
    if (elements.preScanGuidanceCard) elements.preScanGuidanceCard.classList.add('hidden');
    if (elements.resultsPlaceholder) elements.resultsPlaceholder.classList.add('hidden');
    elements.resultsCard.classList.remove('hidden');

    // Risk Tier Styling
    const risk = (data.risk_level || 'LOW').toUpperCase();
    elements.riskBadge.textContent = `${risk} RISK`;
    elements.riskBadge.className = `risk-badge risk-${risk.toLowerCase()}`;

    // Classification
    const classLabel = data.classification || (data.is_suspicious ? 'SPAM' : 'HAM');
    elements.classificationTag.textContent = classLabel.toUpperCase().replace('_', ' ');

    // Score & Meter
    const scorePct = Math.round((data.risk_score || 0) * 100);
    elements.scoreValue.textContent = `${scorePct}%`;
    elements.riskMeterFill.style.width = `${Math.max(5, scorePct)}%`;
    elements.riskMeterFill.className = `risk-meter-fill fill-${risk.toLowerCase()}`;

    // AI Investigation Summary
    const inv = data.investigation || {};
    elements.investigationSummary.textContent = inv.summary || data.score_interpretation;
    elements.investigationProvider.textContent = `Provider: ${inv.provider_used || 'Rule-Based Engine'}`;

    // Multi-Modal Specific Forensic Findings Card
    if (elements.multimodalForensicCard) {
      const hasQr = data.qr_forensics && data.qr_forensics.qr_detected;
      const hasBrands = data.detected_brands && data.detected_brands.length > 0;
      const hasDocText = Boolean(data.extracted_text_preview);

      if (hasQr || hasBrands || hasDocText || data.classification === 'quishing' || data.classification === 'fake_invoice') {
        elements.multimodalForensicCard.classList.remove('hidden');
        elements.multimodalClassificationBadge.textContent = (data.classification || 'DECEPTIVE').toUpperCase().replace('_', ' ');

        // QR Forensics
        if (hasQr) {
          elements.qrForensicRow.classList.remove('hidden');
          const qrRisk = data.qr_forensics.quishing_risk || 'HIGH';
          elements.qrRiskLabel.textContent = qrRisk;
          elements.qrRiskLabel.className = `qr-risk-${qrRisk.toLowerCase()}`;
          elements.qrPayloadCode.textContent = data.qr_forensics.payload;
          elements.qrDomainText.textContent = data.qr_forensics.destination_domain || 'Unverified Domain';
        } else {
          elements.qrForensicRow.classList.add('hidden');
        }

        // Detected Brands
        if (hasBrands) {
          elements.brandsRow.classList.remove('hidden');
          elements.detectedBrandsList.innerHTML = '';
          data.detected_brands.forEach(b => {
            const span = document.createElement('span');
            span.className = 'brand-pill';
            span.textContent = b;
            elements.detectedBrandsList.appendChild(span);
          });
        } else {
          elements.brandsRow.classList.add('hidden');
        }

        // Extracted Document Text Preview
        if (hasDocText) {
          elements.docTextRow.classList.remove('hidden');
          elements.docTextSnippet.textContent = data.extracted_text_preview;
        } else {
          elements.docTextRow.classList.add('hidden');
        }
      } else {
        elements.multimodalForensicCard.classList.add('hidden');
      }
    }

    // Observable Warning Signs
    elements.observableSignsList.innerHTML = '';
    const signs = inv.observable_warning_signs || [];
    if (signs.length === 0) {
      const div = document.createElement('div');
      div.className = 'indicator-badge';
      div.innerHTML = `<span style="color:#A7F3D0">✓ No suspicious security patterns identified.</span>`;
      elements.observableSignsList.appendChild(div);
    } else {
      signs.forEach(sign => {
        const div = document.createElement('div');
        div.className = 'indicator-badge';
        div.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <span>${escapeHtml(sign)}</span>
        `;
        elements.observableSignsList.appendChild(div);
      });
    }

    // Evidence vs Assumptions
    elements.directObservationsList.innerHTML = '';
    const direct = inv.evidence_vs_assumptions?.direct_observations || [];
    direct.forEach(item => {
      const li = document.createElement('li');
      li.textContent = item;
      elements.directObservationsList.appendChild(li);
    });

    elements.potentialImplicationsList.innerHTML = '';
    const implied = inv.evidence_vs_assumptions?.potential_implications || [];
    implied.forEach(item => {
      const li = document.createElement('li');
      li.textContent = item;
      elements.potentialImplicationsList.appendChild(li);
    });

    // Recommended Actions
    elements.recommendedActionsList.innerHTML = '';
    const actions = inv.recommended_actions || [];
    actions.forEach(act => {
      const li = document.createElement('li');
      li.textContent = act;
      elements.recommendedActionsList.appendChild(li);
    });

    // Uncertainty Statement
    elements.uncertaintyText.textContent = inv.uncertainty_statement || 'Model statistical evaluation is not a guarantee of absolute real-world ground truth.';

    // Reset feedback
    elements.feedbackStatusMsg.classList.add('hidden');
    elements.btnFeedbackHelpful.disabled = false;
    elements.btnFeedbackIncorrect.disabled = false;

    // Scroll into view
    elements.resultsCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }


  // --- Feedback Logic ---
  function initFeedback() {
    elements.btnFeedbackHelpful.addEventListener('click', () => submitFeedback(true));
    elements.btnFeedbackIncorrect.addEventListener('click', () => submitFeedback(false));
  }

  async function submitFeedback(isHelpful) {
    if (!currentScanId) return;

    elements.btnFeedbackHelpful.disabled = true;
    elements.btnFeedbackIncorrect.disabled = true;

    try {
      const resp = await fetch(`${API_BASE}/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_id: currentScanId,
          is_helpful: isHelpful,
          user_label: isHelpful ? 'verified' : 'disputed'
        })
      });

      if (resp.ok) {
        elements.feedbackStatusMsg.textContent = isHelpful
          ? '✓ Feedback recorded as helpful. Thank you!'
          : '✓ Noted. Stored in separate audit log.';
        elements.feedbackStatusMsg.classList.remove('hidden');
      }
    } catch (err) {
      showToast('Could not record feedback.', 'error');
    }
  }

  // --- Dashboard Logic ---
  async function loadDashboardMetrics() {
    try {
      const resp = await fetch(`${API_BASE}/metrics`);
      if (!resp.ok) return;
      const data = await resp.json();

      elements.kpiTotalScans.textContent = (data.total_scans || 0).toLocaleString();
      elements.kpiSuspiciousScans.textContent = (data.suspicious_scans || 0).toLocaleString();
      elements.kpiLegitScans.textContent = (data.legitimate_scans || 0).toLocaleString();
      
      const total = data.total_scans || 0;
      const suspPct = total > 0 ? Math.round((data.suspicious_scans / total) * 100) : 0;
      const legitPct = total > 0 ? Math.round((data.legitimate_scans / total) * 100) : 0;
      elements.kpiSuspiciousRate.textContent = `${suspPct}% detection rate`;
      elements.kpiLegitRate.textContent = `${legitPct}% clean rate`;

      const avgRisk = data.average_risk_score || 0;
      elements.kpiAvgRisk.textContent = `${(avgRisk * 100).toFixed(1)}%`;

      // Distribution Bar
      const dist = data.risk_distribution || { LOW: 0, MEDIUM: 0, HIGH: 0 };
      elements.countLow.textContent = dist.LOW || 0;
      elements.countMedium.textContent = dist.MEDIUM || 0;
      elements.countHigh.textContent = dist.HIGH || 0;

      const sum = (dist.LOW || 0) + (dist.MEDIUM || 0) + (dist.HIGH || 0);
      if (sum > 0) {
        elements.barLow.style.width = `${((dist.LOW || 0) / sum) * 100}%`;
        elements.barMedium.style.width = `${((dist.MEDIUM || 0) / sum) * 100}%`;
        elements.barHigh.style.width = `${((dist.HIGH || 0) / sum) * 100}%`;
      } else {
        elements.barLow.style.width = '33.3%';
        elements.barMedium.style.width = '33.3%';
        elements.barHigh.style.width = '33.4%';
      }

      // Recent Stream
      loadRecentInvestigationsStream();
    } catch (err) {
      console.error('Failed to load dashboard metrics', err);
    }
  }

  async function loadRecentInvestigationsStream() {
    try {
      const resp = await fetch(`${API_BASE}/history?limit=5`);
      if (!resp.ok) return;
      const data = await resp.json();

      const emptyState = document.getElementById('dashboardEmptyState');
      const tableWrap = document.getElementById('dashboardTableWrap');

      elements.dashboardRecentTbody.innerHTML = '';
      if (!data.items || data.items.length === 0) {
        if (emptyState) emptyState.classList.remove('hidden');
        if (tableWrap) tableWrap.classList.add('hidden');
        return;
      }

      if (emptyState) emptyState.classList.add('hidden');
      if (tableWrap) tableWrap.classList.remove('hidden');

      data.items.forEach(item => {
        const tr = document.createElement('tr');
        const dt = new Date(item.created_at).toLocaleString();
        tr.innerHTML = `
          <td style="font-family:var(--font-mono);font-size:0.75rem;">${escapeHtml(dt)}</td>
          <td class="table-preview-cell" title="${escapeHtml(item.message_preview)}">${escapeHtml(item.message_preview)}</td>
          <td><span class="classification-tag">${item.classification}</span></td>
          <td><span class="risk-badge risk-${item.risk_level.toLowerCase()} btn-sm">${item.risk_level}</span></td>
          <td style="font-family:var(--font-mono);">${Math.round(item.risk_score * 100)}%</td>
          <td>
            <button type="button" class="btn btn-secondary btn-sm btn-inspect" data-id="${item.id}">Inspect</button>
          </td>
        `;
        elements.dashboardRecentTbody.appendChild(tr);
      });

      // Attach inspect listeners
      elements.dashboardRecentTbody.querySelectorAll('.btn-inspect').forEach(b => {
        b.addEventListener('click', () => openScanDetailModal(b.getAttribute('data-id')));
      });
    } catch (err) {
      console.error('Failed to load recent investigations', err);
    }
  }

  function initDashboard() {
    if (elements.btnRefreshDashboard) {
      elements.btnRefreshDashboard.addEventListener('click', loadDashboardMetrics);
    }
    const btnAnalyze = document.getElementById('btnDashboardOpenScanner');
    if (btnAnalyze) {
      btnAnalyze.addEventListener('click', () => {
        navigateTo('scanner');
        if (elements.messageInput) elements.messageInput.focus();
      });
    }
    const btnEmptyScan = document.getElementById('btnDashboardEmptyScan');
    if (btnEmptyScan) {
      btnEmptyScan.addEventListener('click', () => {
        navigateTo('scanner');
        if (elements.messageInput) elements.messageInput.focus();
      });
    }
    const btnViewAllHistory = document.getElementById('btnDashboardViewAllHistory');
    if (btnViewAllHistory) {
      btnViewAllHistory.addEventListener('click', () => {
        navigateTo('history');
      });
    }
  }

  // --- History & Audit Ledger Logic ---
  function initHistory() {
    elements.btnApplyHistoryFilter.addEventListener('click', loadScanHistory);
    elements.btnResetHistoryFilter.addEventListener('click', () => {
      elements.historyRiskFilter.value = '';
      elements.historySearchInput.value = '';
      loadScanHistory();
    });
    elements.btnClearAllHistory.addEventListener('click', handleClearAllHistory);
  }

  async function loadScanHistory() {
    const risk = elements.historyRiskFilter.value;
    const search = elements.historySearchInput.value.trim();

    elements.historyTbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">Fetching audit records...</td></tr>`;

    let url = `${API_BASE}/history?limit=50`;
    if (risk) url += `&risk_level=${encodeURIComponent(risk)}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    try {
      const resp = await fetch(url, { credentials: 'same-origin' });
      if (!resp.ok) {
        if (resp.status === 401) {
          handleSessionExpired();
          return;
        }
        throw new Error(`Server returned error (${resp.status})`);
      }
      const data = await resp.json();

      if (elements.historyRecordCount) {
        elements.historyRecordCount.textContent = `${data.total || 0} personal audit record(s) found`;
      }
      elements.historyTbody.innerHTML = '';

      if (!data.items || data.items.length === 0) {
        elements.historyTbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No personal audit records found. Run an investigation in the Message Scanner to see it audited here.</td></tr>`;
        return;
      }

      data.items.forEach(item => {
        const tr = document.createElement('tr');
        const dt = new Date(item.created_at).toLocaleString();
        tr.innerHTML = `
          <td style="font-family:var(--font-mono);font-size:0.75rem;">${escapeHtml(dt)}</td>
          <td class="table-preview-cell" title="${escapeHtml(item.message_preview)}">${escapeHtml(item.message_preview)}</td>
          <td><span class="classification-tag">${item.classification}</span></td>
          <td><span class="risk-badge risk-${item.risk_level.toLowerCase()} btn-sm">${item.risk_level}</span></td>
          <td style="font-family:var(--font-mono);">${Math.round(item.risk_score * 100)}%</td>
          <td style="font-size:0.75rem;color:var(--text-muted);">${escapeHtml(item.model_version)}</td>
          <td style="white-space:nowrap;">
            <button type="button" class="btn btn-secondary btn-sm btn-inspect" data-id="${item.id}" title="Inspect analysis">Inspect</button>
            <button type="button" class="btn btn-danger btn-sm btn-delete" data-id="${item.id}" title="Delete record">Delete</button>
          </td>
        `;
        elements.historyTbody.appendChild(tr);
      });

      // Attach button events
      elements.historyTbody.querySelectorAll('.btn-inspect').forEach(b => {
        b.addEventListener('click', () => openScanDetailModal(b.getAttribute('data-id')));
      });

      elements.historyTbody.querySelectorAll('.btn-delete').forEach(b => {
        b.addEventListener('click', () => handleDeleteSingleScan(b.getAttribute('data-id')));
      });

    } catch (err) {
      elements.historyTbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Error loading history: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  async function handleDeleteSingleScan(scanId) {
    if (!confirm('Permanently delete this scan record from storage?')) return;

    try {
      const headers = {};
      if (csrfToken) headers['X-CSRF-Token'] = csrfToken;

      const resp = await fetch(`${API_BASE}/history/${scanId}`, {
        method: 'DELETE',
        headers,
        credentials: 'same-origin'
      });
      if (!resp.ok) {
        const errJson = await resp.json().catch(() => ({}));
        throw new Error(errJson.detail || 'Deletion failed');
      }
      showToast('Record deleted.', 'success');
      loadScanHistory();
      loadDashboardMetrics();
      if (currentUser) checkAuthStatus();
    } catch (err) {
      showToast(`Delete failed: ${err.message}`, 'error');
    }
  }

  async function handleClearAllHistory() {
    if (!confirm('Are you sure you want to clear your private investigation history? This action cannot be undone.')) return;

    try {
      const headers = {};
      if (csrfToken) headers['X-CSRF-Token'] = csrfToken;

      const resp = await fetch(`${API_BASE}/history`, {
        method: 'DELETE',
        headers,
        credentials: 'same-origin'
      });
      if (!resp.ok) {
        const errJson = await resp.json().catch(() => ({}));
        throw new Error(errJson.detail || 'Wipe failed');
      }
      const data = await resp.json();
      showToast(`History cleared (${data.records_removed} records purged).`, 'success');
      loadScanHistory();
      loadDashboardMetrics();
      if (currentUser) checkAuthStatus();
    } catch (err) {
      showToast(`Clear failed: ${err.message}`, 'error');
    }
  }

  // --- Authentication & User Account Logic ---
  function initAuth() {
    // Mode toggles on Auth tab
    if (elements.tabBtnSignIn) {
      elements.tabBtnSignIn.addEventListener('click', () => switchAuthMode('login'));
    }
    if (elements.tabBtnSignUp) {
      elements.tabBtnSignUp.addEventListener('click', () => switchAuthMode('register'));
    }

    if (elements.linkSwitchToSignUp) {
      elements.linkSwitchToSignUp.addEventListener('click', (e) => {
        e.preventDefault();
        switchAuthMode('register');
      });
    }

    if (elements.linkSwitchToSignIn) {
      elements.linkSwitchToSignIn.addEventListener('click', (e) => {
        e.preventDefault();
        switchAuthMode('login');
      });
    }

    if (elements.btnReturnHome) {
      elements.btnReturnHome.addEventListener('click', () => navigateTo('home'));
    }

    if (elements.btnHeaderBackHome) {
      elements.btnHeaderBackHome.addEventListener('click', () => navigateTo('home'));
    }

    if (elements.btnHeaderRegister) {
      elements.btnHeaderRegister.addEventListener('click', () => navigateTo('register'));
    }

    // Password visibility toggles
    setupPasswordToggle(elements.toggleLoginPassword, elements.loginPassword);
    setupPasswordToggle(elements.toggleRegPassword, elements.regPassword);
    setupPasswordToggle(elements.toggleRegConfirmPassword, elements.regConfirmPassword);

    // Form submissions
    if (elements.formLogin) {
      elements.formLogin.addEventListener('submit', handleLogin);
    }
    if (elements.formRegister) {
      elements.formRegister.addEventListener('submit', handleRegister);
    }

    // Header Auth
    if (elements.btnHeaderSignIn) {
      elements.btnHeaderSignIn.addEventListener('click', () => navigateTo('login'));
    }

    if (elements.userMenuToggleBtn) {
      elements.userMenuToggleBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isShown = elements.userDropdownMenu.classList.contains('show');
        elements.userDropdownMenu.classList.toggle('show', !isShown);
        elements.userMenuToggleBtn.setAttribute('aria-expanded', !isShown ? 'true' : 'false');
      });
    }

    // Close user dropdown on outside click
    document.addEventListener('click', (e) => {
      if (elements.headerUserMenu && !elements.headerUserMenu.contains(e.target)) {
        if (elements.userDropdownMenu) elements.userDropdownMenu.classList.remove('show');
        if (elements.userMenuToggleBtn) elements.userMenuToggleBtn.setAttribute('aria-expanded', 'false');
      }
    });

    // Dropdown items
    if (elements.dropdownItemAccount) {
      elements.dropdownItemAccount.addEventListener('click', () => {
        if (elements.userDropdownMenu) elements.userDropdownMenu.classList.remove('show');
        navigateTo('account');
      });
    }

    if (elements.dropdownItemMyScans) {
      elements.dropdownItemMyScans.addEventListener('click', () => {
        if (elements.userDropdownMenu) elements.userDropdownMenu.classList.remove('show');
        currentHistoryScope = 'personal';
        updateHistoryScopeUI();
        switchTab('historyTab');
      });
    }

    if (elements.dropdownItemLogout) {
      elements.dropdownItemLogout.addEventListener('click', () => {
        if (elements.userDropdownMenu) elements.userDropdownMenu.classList.remove('show');
        handleLogout();
      });
    }

    // Account tab buttons
    if (elements.btnAccountViewScans) {
      elements.btnAccountViewScans.addEventListener('click', () => {
        currentHistoryScope = 'personal';
        updateHistoryScopeUI();
        switchTab('historyTab');
      });
    }

    if (elements.btnAccountNewScan) {
      elements.btnAccountNewScan.addEventListener('click', () => switchTab('scannerTab'));
    }

    if (elements.btnAccountLogout) {
      elements.btnAccountLogout.addEventListener('click', handleLogout);
    }

    // History Scope selector
    if (elements.btnScopeGuest) {
      elements.btnScopeGuest.addEventListener('click', () => {
        currentHistoryScope = 'guest';
        updateHistoryScopeUI();
        loadScanHistory();
      });
    }

    if (elements.btnScopePersonal) {
      elements.btnScopePersonal.addEventListener('click', () => {
        if (!currentUser) {
          showToast('Sign in or register to access personal scan history.', 'info');
          navigateTo('login');
          return;
        }
        currentHistoryScope = 'personal';
        updateHistoryScopeUI();
        loadScanHistory();
      });
    }
  }

  function updateHistoryScopeUI() {
    if (elements.btnScopeGuest && elements.btnScopePersonal) {
      const isGuest = currentHistoryScope === 'guest';
      elements.btnScopeGuest.classList.toggle('active', isGuest);
      elements.btnScopeGuest.setAttribute('aria-selected', isGuest ? 'true' : 'false');
      elements.btnScopePersonal.classList.toggle('active', !isGuest);
      elements.btnScopePersonal.setAttribute('aria-selected', !isGuest ? 'true' : 'false');
    }
  }

  function setupPasswordToggle(btn, input) {
    if (!btn || !input) return;
    btn.addEventListener('click', () => {
      const isPassword = input.getAttribute('type') === 'password';
      input.setAttribute('type', isPassword ? 'text' : 'password');
      btn.innerHTML = isPassword
        ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
        : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    });
  }

  function switchAuthMode(mode) {
    clearAuthAlert();
    const isLogin = mode === 'login';
    if (elements.tabBtnSignIn) {
      elements.tabBtnSignIn.classList.toggle('active', isLogin);
      elements.tabBtnSignIn.setAttribute('aria-selected', isLogin ? 'true' : 'false');
    }
    if (elements.tabBtnSignUp) {
      elements.tabBtnSignUp.classList.toggle('active', !isLogin);
      elements.tabBtnSignUp.setAttribute('aria-selected', !isLogin ? 'true' : 'false');
    }
    if (elements.formLogin) elements.formLogin.classList.toggle('hidden', !isLogin);
    if (elements.formRegister) elements.formRegister.classList.toggle('hidden', isLogin);
  }

  function showAuthAlert(msg, type = 'error') {
    if (!elements.authAlertBanner || !elements.authAlertText) return;
    elements.authAlertText.textContent = msg;
    elements.authAlertBanner.className = `auth-alert auth-alert-${type}`;
    elements.authAlertBanner.classList.remove('hidden');
  }

  function clearAuthAlert() {
    if (elements.authAlertBanner) {
      elements.authAlertBanner.classList.add('hidden');
    }
  }

  async function checkAuthStatus() {
    try {
      const resp = await fetch(`${API_BASE}/auth/me`, { credentials: 'same-origin' });
      if (resp.ok) {
        const data = await resp.json();
        currentUser = data.user;
        csrfToken = data.csrf_token;
        updateAuthUI();
      } else {
        currentUser = null;
        csrfToken = null;
        updateAuthUI();
      }
    } catch (err) {
      currentUser = null;
      csrfToken = null;
      updateAuthUI();
    }
  }

  function updateAuthUI() {
    const isAuth = !!currentUser;
    document.body.classList.toggle('authenticated', isAuth);
    document.body.classList.toggle('unauthenticated', !isAuth);

    if (isAuth) {
      if (elements.headerGuestActions) elements.headerGuestActions.style.display = 'none';
      if (elements.headerUserMenu) elements.headerUserMenu.style.display = 'block';

      const firstName = (currentUser.full_name || 'User').split(' ')[0];
      const initial = (currentUser.full_name || 'U').charAt(0).toUpperCase();

      if (elements.userNameLabel) elements.userNameLabel.textContent = firstName;
      if (elements.userAvatarInitial) elements.userAvatarInitial.textContent = initial;
      if (elements.dropdownUserName) elements.dropdownUserName.textContent = currentUser.full_name;
      if (elements.dropdownUserEmail) elements.dropdownUserEmail.textContent = currentUser.email;

      renderAccountDashboard();
    } else {
      const isAuthPage = document.body.classList.contains('auth-page-mode');
      if (elements.headerGuestActions) elements.headerGuestActions.style.display = isAuthPage ? 'none' : 'inline-flex';
      if (elements.headerUserMenu) elements.headerUserMenu.style.display = 'none';
      if (elements.userDropdownMenu) elements.userDropdownMenu.classList.remove('show');
    }
  }

  function renderAccountDashboard() {
    if (!currentUser) return;
    const initial = (currentUser.full_name || 'U').charAt(0).toUpperCase();
    if (elements.accountAvatarLarge) elements.accountAvatarLarge.textContent = initial;
    if (elements.accountProfileName) elements.accountProfileName.textContent = currentUser.full_name;
    if (elements.accountProfileEmail) elements.accountProfileEmail.textContent = currentUser.email;
    if (elements.accountScanCount) elements.accountScanCount.textContent = (currentUser.total_scans || 0).toLocaleString();

    if (elements.accountMemberSince && currentUser.created_at) {
      const d = new Date(currentUser.created_at);
      elements.accountMemberSince.textContent = d.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    }
  }

  async function handleLogin(e) {
    e.preventDefault();
    clearAuthAlert();

    const email = elements.loginEmail ? elements.loginEmail.value.trim() : '';
    const password = elements.loginPassword ? elements.loginPassword.value : '';

    if (!email || !password) {
      showAuthAlert('Please enter both your email address and password.', 'error');
      return;
    }

    elements.btnLoginSubmit.disabled = true;
    if (elements.loginSpinner) elements.loginSpinner.classList.remove('hidden');
    if (elements.loginBtnText) elements.loginBtnText.textContent = 'Verifying...';

    try {
      const resp = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ email, password })
      });

      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        throw new Error(data.detail || 'Sign in failed. Please check your credentials.');
      }

      currentUser = data.user;
      csrfToken = data.csrf_token;
      updateAuthUI();

      if (elements.loginPassword) elements.loginPassword.value = '';

      let dest = authReturnDestination || 'dashboard';
      authReturnDestination = null;
      if (!VALID_RETURN_ROUTES.includes(dest)) dest = 'dashboard';

      showToast(`Welcome back, ${currentUser.full_name.split(' ')[0]}!`, 'success');
      navigateTo(dest);
    } catch (err) {
      showAuthAlert(err.message, 'error');
    } finally {
      elements.btnLoginSubmit.disabled = false;
      if (elements.loginSpinner) elements.loginSpinner.classList.add('hidden');
      if (elements.loginBtnText) elements.loginBtnText.textContent = 'Sign In to Workspace';
    }
  }

  async function handleRegister(e) {
    e.preventDefault();
    clearAuthAlert();

    const full_name = elements.regFullName ? elements.regFullName.value.trim() : '';
    const email = elements.regEmail ? elements.regEmail.value.trim().toLowerCase() : '';
    const password = elements.regPassword ? elements.regPassword.value : '';
    const confirm_password = elements.regConfirmPassword ? elements.regConfirmPassword.value : '';

    if (!full_name || full_name.length < 2) {
      showAuthAlert('Please enter your full name (minimum 2 characters).', 'error');
      return;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
      showAuthAlert('Please enter a valid email address (e.g. analyst@organization.com).', 'error');
      return;
    }
    if (password.length < 8) {
      showAuthAlert('Password must be at least 8 characters long.', 'error');
      return;
    }
    if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      showAuthAlert('Password must contain both letters and digits.', 'error');
      return;
    }
    if (password !== confirm_password) {
      showAuthAlert('Passwords do not match. Please re-enter your password.', 'error');
      return;
    }

    elements.btnRegisterSubmit.disabled = true;
    if (elements.regSpinner) elements.regSpinner.classList.remove('hidden');
    if (elements.regBtnText) elements.regBtnText.textContent = 'Creating Account...';

    try {
      const resp = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ full_name, email, password, confirm_password })
      });

      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        throw new Error(data.detail || 'Registration failed.');
      }

      currentUser = data.user;
      csrfToken = data.csrf_token;
      updateAuthUI();

      if (elements.regPassword) elements.regPassword.value = '';
      if (elements.regConfirmPassword) elements.regConfirmPassword.value = '';

      let dest = authReturnDestination || 'dashboard';
      authReturnDestination = null;
      if (!VALID_RETURN_ROUTES.includes(dest)) dest = 'dashboard';

      showToast(`Account created! Welcome, ${currentUser.full_name.split(' ')[0]}.`, 'success');
      navigateTo(dest);
    } catch (err) {
      showAuthAlert(err.message, 'error');
    } finally {
      elements.btnRegisterSubmit.disabled = false;
      if (elements.regSpinner) elements.regSpinner.classList.add('hidden');
      if (elements.regBtnText) elements.regBtnText.textContent = 'Create Security Account';
    }
  }

  async function handleLogout() {
    try {
      const headers = {};
      if (csrfToken) headers['X-CSRF-Token'] = csrfToken;

      await fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        headers,
        credentials: 'same-origin'
      });
    } catch (err) {
      // Continue client cleanup even if network fails
    }

    currentUser = null;
    csrfToken = null;
    authReturnDestination = null;
    currentScanId = null;

    // Reset scanner inputs and clear private data
    if (elements.messageInput) elements.messageInput.value = '';
    if (elements.resultsCard) elements.resultsCard.classList.add('hidden');
    if (elements.preScanGuidanceCard) elements.preScanGuidanceCard.classList.remove('hidden');
    if (elements.historyTbody) elements.historyTbody.innerHTML = '';
    if (elements.dashboardRecentTbody) elements.dashboardRecentTbody.innerHTML = '';

    updateAuthUI();
    showToast('Signed out successfully. Session terminated.', 'info');
    navigateTo('home');
  }

  function handleSessionExpired() {
    currentUser = null;
    csrfToken = null;
    authReturnDestination = null;
    updateAuthUI();
    showToast('Your session has expired. Please sign in to continue.', 'error');
    navigateTo('login');
  }

  // --- Modal Logic ---
  function initModal() {
    elements.btnCloseModal.addEventListener('click', closeModal);
    elements.btnModalDismiss.addEventListener('click', closeModal);
    elements.detailModal.addEventListener('click', (e) => {
      if (e.target === elements.detailModal) closeModal();
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !elements.detailModal.classList.contains('hidden')) {
        closeModal();
      }
    });
  }

  function closeModal() {
    elements.detailModal.classList.add('hidden');
  }

  async function openScanDetailModal(scanId) {
    elements.modalBodyContent.innerHTML = '<p class="text-muted">Loading audit details...</p>';
    elements.detailModal.classList.remove('hidden');

    try {
      const resp = await fetch(`${API_BASE}/history/${scanId}`);
      if (!resp.ok) throw new Error('Could not retrieve scan details');
      const item = await resp.json();

      const inv = item.investigation || {};
      const indicators = item.observable_indicators || {};
      const dt = new Date(item.created_at).toLocaleString();

      elements.modalBodyContent.innerHTML = `
        <div style="margin-bottom:16px;">
          <div style="font-size:0.75rem;color:var(--text-muted);font-family:var(--font-mono);">Record ID: ${escapeHtml(item.id)}</div>
          <div style="font-size:0.75rem;color:var(--text-muted);">Timestamp: ${escapeHtml(dt)}</div>
        </div>

        <div style="margin-bottom:16px;">
          <h4 style="font-size:0.85rem;text-transform:uppercase;color:var(--text-secondary);margin-bottom:6px;">Sanitized Message Preview</h4>
          <div style="background-color:var(--navy-darkest);padding:10px;border-radius:4px;font-family:var(--font-mono);font-size:0.85rem;border:1px solid var(--border-subtle);">${escapeHtml(item.message_preview)}</div>
        </div>

        <div style="display:flex;gap:12px;margin-bottom:16px;align-items:center;">
          <span class="risk-badge risk-${item.risk_level.toLowerCase()}">${item.risk_level} RISK</span>
          <span class="classification-tag">${item.classification}</span>
          <span style="font-family:var(--font-mono);font-size:1.1rem;font-weight:700;">${Math.round(item.risk_score * 100)}%</span>
        </div>

        <div style="margin-bottom:16px;">
          <h4 style="font-size:0.85rem;text-transform:uppercase;color:var(--text-secondary);margin-bottom:6px;">Executive AI Summary</h4>
          <p style="font-size:0.9rem;color:#E2E8F0;line-height:1.5;">${escapeHtml(inv.summary || 'No summary recorded.')}</p>
        </div>

        <div style="margin-bottom:16px;">
          <h4 style="font-size:0.85rem;text-transform:uppercase;color:var(--text-secondary);margin-bottom:6px;">Recommended Actions</h4>
          <ul style="padding-left:20px;font-size:0.85rem;color:#CBD5E1;line-height:1.6;">
            ${(inv.recommended_actions || ['Standard caution advised.']).map(a => `<li>${escapeHtml(a)}</li>`).join('')}
          </ul>
        </div>
      `;
    } catch (err) {
      elements.modalBodyContent.innerHTML = `<p class="text-danger">Failed to load details: ${escapeHtml(err.message)}</p>`;
    }
  }

  // --- Threat Samples Library ---
  async function loadSampleMessages() {
    try {
      const resp = await fetch(`${API_BASE}/samples`);
      if (!resp.ok) return;
      const samples = await resp.json();
      sampleMessagesCache = samples;

      // Populate Quick Sample Dropdown
      elements.quickSampleSelect.innerHTML = '<option value="">Load a threat sample...</option>';
      samples.forEach(s => {
        const opt = document.createElement('option');
        opt.value = s.id;
        opt.textContent = `${s.expected_risk === 'HIGH' ? '⚠️' : '✓'} ${s.title}`;
        elements.quickSampleSelect.appendChild(opt);
      });

      // Populate Samples Gallery Tab
      elements.samplesGallery.innerHTML = '';
      samples.forEach(s => {
        const card = document.createElement('div');
        card.className = 'sample-card';
        card.innerHTML = `
          <div>
            <div class="sample-header">
              <span class="sample-category">${escapeHtml(s.category)}</span>
              <span class="risk-badge risk-${s.expected_risk.toLowerCase()} btn-sm">${s.expected_risk}</span>
            </div>
            <h3 class="sample-title">${escapeHtml(s.title)}</h3>
            <p class="sample-desc">${escapeHtml(s.description)}</p>
            <div class="sample-snippet">${escapeHtml(s.text)}</div>
          </div>
          <button type="button" class="btn btn-primary btn-sm btn-load-sample" data-id="${s.id}">
            Load into Scanner & Investigate
          </button>
        `;
        elements.samplesGallery.appendChild(card);
      });

      // Attach button clicks
      elements.samplesGallery.querySelectorAll('.btn-load-sample').forEach(btn => {
        btn.addEventListener('click', () => {
          const sampleId = btn.getAttribute('data-id');
          const sample = sampleMessagesCache.find(s => s.id === sampleId);
          if (sample) {
            elements.messageInput.value = sample.text;
            elements.messageInput.dispatchEvent(new Event('input'));
            switchTab('scannerTab');
            handleAnalyze();
          }
        });
      });

    } catch (err) {
      console.error('Failed to load sample messages', err);
    }
  }

  // --- AI Investigation Copilot Logic ---
  let progressTimer = null;
  let progressStartTime = 0;

  function initCopilot() {
    if (!elements.copilotSuggestionsList) return;

    // Suggested inquiry chips delegation
    elements.copilotSuggestionsList.addEventListener('click', (e) => {
      const chip = e.target.closest('.copilot-chip');
      if (chip) {
        const question = chip.getAttribute('data-question') || chip.textContent.replace(/→$/, '').trim();
        askCopilot(question);
      }
    });

    // Send button click
    if (elements.btnSendCopilotQuery) {
      elements.btnSendCopilotQuery.addEventListener('click', () => {
        const q = elements.copilotQueryInput ? elements.copilotQueryInput.value.trim() : '';
        if (q) {
          elements.copilotQueryInput.value = '';
          askCopilot(q);
        }
      });
    }

    // Input Enter key press
    if (elements.copilotQueryInput) {
      elements.copilotQueryInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          const q = elements.copilotQueryInput.value.trim();
          if (q) {
            elements.copilotQueryInput.value = '';
            askCopilot(q);
          }
        }
      });
    }
  }

  function startInvestigationProgress() {
    if (!elements.copilotProgressBox) return;
    elements.copilotProgressBox.classList.remove('hidden');

    const stepItems = [elements.stepSanitize, elements.stepInference, elements.stepIndicators, elements.stepSynthesis];
    const statusTags = [elements.statusStep1, elements.statusStep2, elements.statusStep3, elements.statusStep4];

    stepItems.forEach(item => { if (item) item.className = 'progress-step-item'; });
    statusTags.forEach(tag => { if (tag) tag.textContent = 'Pending'; });

    if (elements.stepSanitize) elements.stepSanitize.className = 'progress-step-item step-active';
    if (elements.statusStep1) elements.statusStep1.textContent = 'Active';

    progressStartTime = Date.now();
    if (progressTimer) clearInterval(progressTimer);
    progressTimer = setInterval(() => {
      const elapsed = ((Date.now() - progressStartTime) / 1000).toFixed(1);
      if (elements.progressTimeElapsed) {
        elements.progressTimeElapsed.textContent = `${elapsed}s`;
      }
    }, 100);

    setTimeout(() => {
      if (elements.stepSanitize) elements.stepSanitize.className = 'progress-step-item step-done';
      if (elements.statusStep1) elements.statusStep1.textContent = 'Done ✓';
      if (elements.stepInference) elements.stepInference.className = 'progress-step-item step-active';
      if (elements.statusStep2) elements.statusStep2.textContent = 'Active';
    }, 200);

    setTimeout(() => {
      if (elements.stepInference) elements.stepInference.className = 'progress-step-item step-done';
      if (elements.statusStep2) elements.statusStep2.textContent = 'Done ✓';
      if (elements.stepIndicators) elements.stepIndicators.className = 'progress-step-item step-active';
      if (elements.statusStep3) elements.statusStep3.textContent = 'Active';
    }, 450);

    setTimeout(() => {
      if (elements.stepIndicators) elements.stepIndicators.className = 'progress-step-item step-done';
      if (elements.statusStep3) elements.statusStep3.textContent = 'Done ✓';
      if (elements.stepSynthesis) elements.stepSynthesis.className = 'progress-step-item step-active';
      if (elements.statusStep4) elements.statusStep4.textContent = 'Synthesizing...';
    }, 700);
  }

  function finishInvestigationProgress(success = true) {
    if (progressTimer) {
      clearInterval(progressTimer);
      progressTimer = null;
    }

    if (!elements.copilotProgressBox) return;

    if (success) {
      if (elements.stepSynthesis) elements.stepSynthesis.className = 'progress-step-item step-done';
      if (elements.statusStep4) elements.statusStep4.textContent = 'Done ✓';
      if (elements.progressTimeElapsed) elements.progressTimeElapsed.textContent = 'Complete ✓';

      setTimeout(() => {
        elements.copilotProgressBox.classList.add('hidden');
      }, 2400);
    } else {
      if (elements.stepSynthesis) elements.stepSynthesis.className = 'progress-step-item';
      if (elements.statusStep4) elements.statusStep4.textContent = 'Error';
      if (elements.progressTimeElapsed) elements.progressTimeElapsed.textContent = 'Failed';
      setTimeout(() => {
        elements.copilotProgressBox.classList.add('hidden');
      }, 3500);
    }
  }

  function addCopilotBriefing(result) {
    if (!elements.copilotChatFeed) return;

    const risk = (result.risk_level || 'LOW').toUpperCase();
    const scorePct = Math.round((result.risk_score || 0) * 100);
    const classification = (result.classification || (result.is_suspicious ? 'SPAM' : 'HAM')).toUpperCase();
    const inv = result.investigation || {};
    const summary = inv.summary || result.score_interpretation || 'Investigation completed.';

    const briefingDiv = document.createElement('div');
    briefingDiv.className = 'copilot-msg copilot-msg-ai';
    briefingDiv.innerHTML = `
      <div class="msg-avatar-mini">
        <img src="/static/img/assistant-avatar.jpg" alt="TrustLens AI">
      </div>
      <div class="msg-bubble">
        <div class="msg-sender">TrustLens Copilot — Scan Briefing</div>
        <div class="msg-text">
          <div class="copilot-briefing-box">
            <span class="briefing-badge briefing-badge-${risk === 'HIGH' ? 'high' : (risk === 'MEDIUM' ? 'med' : 'low')}">${risk} RISK (${scorePct}%)</span>
            <strong>${escapeHtml(classification)}</strong>
            <p style="margin-top:6px;font-size:0.8rem;color:var(--text-secondary);">${escapeHtml(summary)}</p>
          </div>
          <p style="margin-top:8px;font-size:0.78rem;color:var(--text-muted);">
            Click any suggested inquiry below or ask a custom question to inspect evidence and safety procedures.
          </p>
        </div>
      </div>
    `;

    elements.copilotChatFeed.appendChild(briefingDiv);
    elements.copilotChatFeed.scrollTop = elements.copilotChatFeed.scrollHeight;

    // Update contextual inquiry chips
    updateSuggestedChips(result);
  }

  function updateSuggestedChips(result) {
    if (!elements.copilotSuggestionsList) return;

    const risk = (result.risk_level || 'LOW').toUpperCase();
    const questions = [];

    if (risk === 'HIGH' || risk === 'MEDIUM' || result.is_suspicious) {
      questions.push('Why is this message suspicious?');
      questions.push('What evidence supports the prediction?');
      questions.push('Which phrases are warning signs?');
      questions.push('What should I do next?');
    } else {
      questions.push('Why was this classified as legitimate?');
      questions.push('What evidence supports the prediction?');
      questions.push('What should I do next?');
      questions.push('Are there subtle risks to watch for?');
    }

    elements.copilotSuggestionsList.innerHTML = '';
    questions.forEach(q => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'copilot-chip';
      btn.setAttribute('data-question', q);
      btn.textContent = q;
      elements.copilotSuggestionsList.appendChild(btn);
    });
  }

  async function askCopilot(questionText) {
    if (!questionText || !questionText.trim()) return;
    const cleanQ = questionText.trim();

    // 1. Append User Bubble
    const userMsg = document.createElement('div');
    userMsg.className = 'copilot-msg copilot-msg-user';
    userMsg.innerHTML = `
      <div class="msg-bubble">
        <div class="msg-sender">You</div>
        <div class="msg-text">${escapeHtml(cleanQ)}</div>
      </div>
    `;
    elements.copilotChatFeed.appendChild(userMsg);

    // 2. Append Thinking Indicator
    const thinkingMsg = document.createElement('div');
    thinkingMsg.className = 'copilot-msg copilot-msg-ai';
    thinkingMsg.id = 'copilotThinkingBubble';
    thinkingMsg.innerHTML = `
      <div class="msg-avatar-mini">
        <img src="/static/img/assistant-avatar.jpg" alt="AI">
      </div>
      <div class="msg-bubble">
        <div class="msg-sender">TrustLens Copilot</div>
        <div class="msg-text">
          <span class="btn-spinner" style="display:inline-block;vertical-align:middle;margin-right:6px;width:12px;height:12px;border-width:2px;border-color:rgba(37,99,235,0.3);border-top-color:#2563EB;"></span>
          Analyzing inquiry context...
        </div>
      </div>
    `;
    elements.copilotChatFeed.appendChild(thinkingMsg);
    elements.copilotChatFeed.scrollTop = elements.copilotChatFeed.scrollHeight;

    // 3. Make real API request
    try {
      const payload = {
        question: cleanQ,
        scan_id: currentScanId,
        message: elements.messageInput ? elements.messageInput.value.trim() : null
      };

      const resp = await fetch(`${API_BASE}/copilot/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!resp.ok) {
        const errorData = await resp.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server returned ${resp.status}`);
      }

      const data = await resp.json();

      // Remove thinking bubble
      thinkingMsg.remove();

      // Format markdown answer to clean HTML
      const formattedAnswer = formatMarkdownToHtml(data.answer);

      const aiMsg = document.createElement('div');
      aiMsg.className = 'copilot-msg copilot-msg-ai';
      aiMsg.innerHTML = `
        <div class="msg-avatar-mini">
          <img src="/static/img/assistant-avatar.jpg" alt="TrustLens AI">
        </div>
        <div class="msg-bubble">
          <div class="msg-sender">TrustLens Copilot <span style="font-size:0.65rem;font-weight:500;color:var(--text-muted);text-transform:none;">(${data.provider_used === 'amazon_bedrock' ? 'Amazon Bedrock' : 'Rule-Based Engine'})</span></div>
          <div class="msg-text">${formattedAnswer}</div>
        </div>
      `;
      elements.copilotChatFeed.appendChild(aiMsg);
      elements.copilotChatFeed.scrollTop = elements.copilotChatFeed.scrollHeight;

      // Update follow-up chips if provided
      if (data.suggested_followups && data.suggested_followups.length > 0) {
        elements.copilotSuggestionsList.innerHTML = '';
        data.suggested_followups.forEach(f => {
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'copilot-chip';
          btn.setAttribute('data-question', f);
          btn.textContent = f;
          elements.copilotSuggestionsList.appendChild(btn);
        });
      }

    } catch (err) {
      thinkingMsg.remove();
      const errorMsg = document.createElement('div');
      errorMsg.className = 'copilot-msg copilot-msg-ai';
      errorMsg.innerHTML = `
        <div class="msg-avatar-mini">
          <img src="/static/img/assistant-avatar.jpg" alt="AI">
        </div>
        <div class="msg-bubble" style="border-color:var(--risk-high-border);background-color:var(--risk-high-bg);">
          <div class="msg-sender" style="color:var(--risk-high-text);">TrustLens Copilot — Notice</div>
          <div class="msg-text" style="color:var(--risk-high-text);">
            I encountered an issue retrieving the response: ${escapeHtml(err.message)}. The statistical ML pipeline remains fully functional.
          </div>
        </div>
      `;
      elements.copilotChatFeed.appendChild(errorMsg);
      elements.copilotChatFeed.scrollTop = elements.copilotChatFeed.scrollHeight;
    }
  }

  function formatMarkdownToHtml(text) {
    if (!text) return '';
    let html = escapeHtml(text);
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
    const lines = html.split('\n');
    let inList = false;
    let result = '';

    for (let line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('• ') || trimmed.startsWith('- ')) {
        if (!inList) {
          result += '<ul>';
          inList = true;
        }
        result += `<li>${trimmed.substring(2)}</li>`;
      } else {
        if (inList) {
          result += '</ul>';
          inList = false;
        }
        if (trimmed.length > 0) {
          result += `<p>${trimmed}</p>`;
        }
      }
    }
    if (inList) result += '</ul>';
    return result;
  }

  // --- Alexa+ Simulated Experience Logic (Amazon Developer Hackathon Track) ---
  let currentAlexaScanId = null;
  let currentAlexaScanData = null;
  let alexaPresetsCache = [];

  function initAlexaSimulator() {
    if (!elements.alexaChatFeed) return;

    // 1. Load preset scenarios
    loadAlexaPresets();

    // 2. Preset scenario click delegation
    if (elements.alexaPresetsGrid) {
      elements.alexaPresetsGrid.addEventListener('click', (e) => {
        const btn = e.target.closest('.alexa-preset-btn');
        if (btn) {
          const scenarioId = btn.getAttribute('data-scenario');
          const scenario = alexaPresetsCache.find(p => p.id === scenarioId);
          if (scenario) {
            if (elements.alexaQueryInput) {
              elements.alexaQueryInput.value = scenario.message;
              updateAlexaCharCount();
            }
            submitAlexaTurn(scenario.message);
          }
        }
      });
    }

    // 3. Suggested inquiry chips click delegation
    elements.alexaChatFeed.addEventListener('click', (e) => {
      const chip = e.target.closest('.alexa-chip');
      if (chip) {
        const promptText = chip.getAttribute('data-prompt') || chip.textContent.replace(/→$/, '').trim();
        if (promptText) {
          submitAlexaTurn(promptText);
        }
      }
    });

    // 4. Send button click
    if (elements.btnSendAlexaQuery) {
      elements.btnSendAlexaQuery.addEventListener('click', () => {
        submitAlexaTurn();
      });
    }

    // 5. Input keydown (Enter to send, Shift+Enter for newline)
    if (elements.alexaQueryInput) {
      elements.alexaQueryInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          submitAlexaTurn();
        }
      });

      elements.alexaQueryInput.addEventListener('input', () => {
        updateAlexaCharCount();
      });
    }

    // 6. Reset session button
    if (elements.btnResetAlexaChat) {
      elements.btnResetAlexaChat.addEventListener('click', () => {
        resetAlexaSession();
      });
    }

    // 7. MCP Tools Inspection Modal
    if (elements.btnViewMcpTools) {
      elements.btnViewMcpTools.addEventListener('click', openMcpToolsModal);
    }
    if (elements.btnCloseMcpModal) {
      elements.btnCloseMcpModal.addEventListener('click', closeMcpToolsModal);
    }
    if (elements.btnDismissMcpModal) {
      elements.btnDismissMcpModal.addEventListener('click', closeMcpToolsModal);
    }
    if (elements.modalMcpTools) {
      elements.modalMcpTools.addEventListener('click', (e) => {
        if (e.target === elements.modalMcpTools) closeMcpToolsModal();
      });
    }
  }

  async function loadAlexaPresets() {
    try {
      const resp = await fetch(`${API_BASE}/alexa/presets`);
      if (resp.ok) {
        alexaPresetsCache = await resp.json();
      }
    } catch (err) {
      // Fallback presets if offline
      alexaPresetsCache = [
        {
          id: 'bank_phishing',
          title: 'Chase Bank Alert',
          category: 'High Risk Smishing',
          message: 'CHASE ALERT: Your account has been temporarily locked due to unusual debit activity. Verify your identity immediately to prevent suspension: http://chase-security-verify.net/login'
        },
        {
          id: 'parcel_smishing',
          title: 'USPS Package Fee Scam',
          category: 'High Risk Smishing',
          message: 'USPS Notification: Package #US984210 cannot be delivered due to missing house number and an unpaid customs fee of $2.49. Update address and pay online within 12h: http://usps-track-redelivery.org'
        },
        {
          id: 'lottery_fraud',
          title: 'Lottery Winner Scam',
          category: 'High Risk Fraud',
          message: 'CONGRATULATIONS! You have been selected as the 2nd place winner of £1,000,000 cash in the National Lottery. Call 08712345678 immediately with your claim code WIN992 to arrange disbursement.'
        },
        {
          id: 'legit_appointment',
          title: 'Doctor Appointment',
          category: 'Legitimate (Clean HAM)',
          message: 'Hey Alex, confirming our doctor appointment tomorrow at 2:30 PM with Dr. Miller at the clinic. See you then!'
        }
      ];
    }
  }

  function updateAlexaCharCount() {
    if (!elements.alexaQueryInput || !elements.alexaInputCharCount) return;
    const len = elements.alexaQueryInput.value.length;
    elements.alexaInputCharCount.textContent = `${len} / 1500 chars`;
    if (len > 1400) {
      elements.alexaInputCharCount.style.color = 'var(--risk-high)';
    } else {
      elements.alexaInputCharCount.style.color = 'var(--text-muted)';
    }
  }

  function resetAlexaSession() {
    currentAlexaScanId = null;
    currentAlexaScanData = null;
    if (elements.alexaQueryInput) {
      elements.alexaQueryInput.value = '';
      updateAlexaCharCount();
    }

    if (elements.alexaChatFeed) {
      elements.alexaChatFeed.innerHTML = `
        <div class="alexa-msg alexa-msg-assistant">
          <div class="alexa-avatar-sm">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
          </div>
          <div class="alexa-bubble">
            <div class="alexa-sender-tag">
              <span>Alexa+ Assistant &bull; TrustLens AI Agent Skill</span>
              <span class="alexa-tool-badge">Session Reset</span>
            </div>
            <div class="alexa-spoken-text">
              <p>Conversation session reset. I am ready to inspect a new communication.</p>
              <p>Click any quick-test scenario above or paste an untrusted message below.</p>
            </div>
            <div class="alexa-chips-wrap">
              <button type="button" class="alexa-chip" data-prompt="Check Chase bank alert sample">Check Chase bank alert sample &rarr;</button>
              <button type="button" class="alexa-chip" data-prompt="Check USPS delivery fee sample">Check USPS delivery fee sample &rarr;</button>
              <button type="button" class="alexa-chip" data-prompt="Check doctor appointment sample">Check doctor appointment sample &rarr;</button>
              <button type="button" class="alexa-chip" data-prompt="What can you do?">What can you do? &rarr;</button>
            </div>
          </div>
        </div>
      `;
    }
    showToast('Alexa+ conversational session reset.', 'info');
  }

  async function openMcpToolsModal() {
    if (!elements.modalMcpTools) return;
    elements.modalMcpTools.classList.remove('hidden');

    if (elements.mcpToolsCodeBlock) {
      elements.mcpToolsCodeBlock.textContent = 'Loading MCP Tool Definitions...';
      try {
        const resp = await fetch(`${API_BASE}/alexa/tools`);
        if (resp.ok) {
          const data = await resp.json();
          elements.mcpToolsCodeBlock.textContent = JSON.stringify(data, null, 2);
        } else {
          elements.mcpToolsCodeBlock.textContent = 'Could not load MCP tools schema from backend.';
        }
      } catch (err) {
        elements.mcpToolsCodeBlock.textContent = `Error fetching tools: ${err.message}`;
      }
    }
  }

  function closeMcpToolsModal() {
    if (elements.modalMcpTools) {
      elements.modalMcpTools.classList.add('hidden');
    }
  }

  async function submitAlexaTurn(overrideText = null) {
    if (!elements.alexaChatFeed) return;

    const query = (overrideText !== null ? overrideText : (elements.alexaQueryInput ? elements.alexaQueryInput.value : '')).trim();
    if (!query) return;

    // Clear input field if from textarea
    if (elements.alexaQueryInput && overrideText === null) {
      elements.alexaQueryInput.value = '';
      updateAlexaCharCount();
    }

    // 1. Render User Message Bubble
    const userMsg = document.createElement('div');
    userMsg.className = 'alexa-msg alexa-msg-user';
    userMsg.innerHTML = `
      <div class="user-avatar-sm">You</div>
      <div class="alexa-bubble">
        <div class="alexa-sender-tag" style="color:rgba(255,255,255,0.7);border-bottom:none;padding-bottom:0;">
          <span>You</span>
        </div>
        <div class="alexa-spoken-text">${escapeHtml(query)}</div>
      </div>
    `;
    elements.alexaChatFeed.appendChild(userMsg);
    elements.alexaChatFeed.scrollTop = elements.alexaChatFeed.scrollHeight;

    // 2. Show Thinking Indicator
    if (elements.alexaThinkingIndicator) {
      elements.alexaThinkingIndicator.classList.remove('hidden');
      elements.alexaChatFeed.appendChild(elements.alexaThinkingIndicator);
      elements.alexaChatFeed.scrollTop = elements.alexaChatFeed.scrollHeight;
    }

    // 3. Dispatch to Alexa+ Simulation API Endpoint
    try {
      const payload = {
        user_prompt: query,
        active_scan_id: currentAlexaScanId,
        active_scan_data: currentAlexaScanData
      };

      const resp = await fetch(`${API_BASE}/alexa/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!resp.ok) {
        const errorData = await resp.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server returned status ${resp.status}`);
      }

      const data = await resp.json();

      // Hide thinking indicator
      if (elements.alexaThinkingIndicator) {
        elements.alexaThinkingIndicator.classList.add('hidden');
      }

      // Update active scan state
      if (data.scan_id) {
        currentAlexaScanId = data.scan_id;
      }
      if (data.scan_result) {
        currentAlexaScanData = {
          scan_id: data.scan_id,
          message_text: data.scan_result.message_analyzed,
          ml_result: {
            classification: data.scan_result.classification,
            risk_score: data.scan_result.risk_score,
            risk_level: data.scan_result.risk_level,
            is_suspicious: data.scan_result.is_suspicious,
            model_name: data.scan_result.model_name,
            model_version: data.scan_result.model_version
          },
          investigation: {
            summary: data.scan_result.summary,
            observable_warning_signs: data.scan_result.warning_signs,
            evidence_vs_assumptions: {
              direct_observations: data.scan_result.direct_observations,
              potential_implications: data.scan_result.potential_implications
            },
            recommended_actions: data.scan_result.recommended_actions,
            uncertainty_statement: data.scan_result.uncertainty_statement,
            provider_used: data.scan_result.provider_used
          },
          scan_result: data.scan_result
        };
      }

      // 4. Build Alexa+ Assistant Message Bubble
      const assistantMsg = document.createElement('div');
      assistantMsg.className = 'alexa-msg alexa-msg-assistant';

      const toolBadgeText = data.tool_invoked
        ? `MCP Tool: ${escapeHtml(data.tool_invoked)}`
        : `Provider: ${data.provider_used === 'amazon_bedrock' ? 'Amazon Bedrock' : 'Rule-Based Engine'}`;

      let scanCardHtml = '';
      if (data.scan_result) {
        const sr = data.scan_result;
        const risk = (sr.risk_level || 'LOW').toUpperCase();
        const score = Math.round((sr.risk_score || 0) * 100);
        const classification = (sr.classification || (sr.is_suspicious ? 'SPAM' : 'HAM')).toUpperCase();
        const riskClass = risk === 'HIGH' ? 'high' : (risk === 'MEDIUM' ? 'medium' : 'low');

        // Indicators pills
        const indicators = sr.observable_indicators || {};
        let pillsHtml = '';
        if (indicators.urls_detected && indicators.urls_detected.length > 0) {
          pillsHtml += `<span class="alexa-indicator-pill pill-alert">🔗 URL: ${escapeHtml(indicators.urls_detected[0])}</span>`;
        }
        if (indicators.urgency_cues && indicators.urgency_cues.length > 0) {
          pillsHtml += `<span class="alexa-indicator-pill pill-alert">⚠️ Urgency: ${escapeHtml(indicators.urgency_cues.slice(0, 2).join(', '))}</span>`;
        }
        if (indicators.currencies_detected && indicators.currencies_detected.length > 0) {
          pillsHtml += `<span class="alexa-indicator-pill pill-alert">💰 Money: ${escapeHtml(indicators.currencies_detected.slice(0, 2).join(', '))}</span>`;
        }
        if (indicators.phones_detected && indicators.phones_detected.length > 0) {
          pillsHtml += `<span class="alexa-indicator-pill">📞 Phone: ${escapeHtml(indicators.phones_detected[0])}</span>`;
        }
        if (!pillsHtml) {
          pillsHtml = `<span class="alexa-indicator-pill">✓ No overt regex threat indicators detected</span>`;
        }

        // Direct observations list
        const directList = (sr.direct_observations || ['Statistical inference completed.'])
          .map(item => `<li>${escapeHtml(item)}</li>`).join('');

        // Implications list
        const impList = (sr.potential_implications || ['Context conforms to standard communication conventions.'])
          .map(item => `<li>${escapeHtml(item)}</li>`).join('');

        // Recommended actions list
        const actionsList = (sr.recommended_actions || ['Exercise standard caution.'])
          .map(item => `<li><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="color:#16A34A;flex-shrink:0;margin-top:2px;"><polyline points="20 6 9 17 4 12"/></svg> ${escapeHtml(item)}</li>`).join('');

        scanCardHtml = `
          <div class="alexa-scan-card">
            <div class="alexa-card-header">
              <div class="alexa-findings-label">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                TrustLens Backend Findings (Real ML &amp; NLP Output)
              </div>
              <span class="alexa-risk-badge badge-risk-${riskClass}">
                ${risk} RISK &bull; ${score}% (${classification})
              </span>
            </div>

            <!-- Risk Meter -->
            <div class="alexa-risk-meter-wrap">
              <div class="alexa-meter-labels">
                <span>0% (Legitimate)</span>
                <span>Evaluated Risk: ${score}%</span>
                <span>100% (High Fraud)</span>
              </div>
              <div class="alexa-meter-track">
                <div class="alexa-meter-fill fill-${riskClass}" style="width: ${Math.max(5, score)}%;"></div>
              </div>
            </div>

            <!-- Observable Threat Indicators -->
            <div class="alexa-indicators-wrap">
              <span class="alexa-indicators-label">Observable Warning Signals Detected:</span>
              <div class="alexa-pills-row">
                ${pillsHtml}
              </div>
            </div>

            <!-- Evidence Grid -->
            <div class="alexa-evidence-grid">
              <div class="alexa-evidence-col">
                <div class="alexa-col-title">Direct Observations (Facts)</div>
                <ul class="alexa-col-list">
                  ${directList}
                </ul>
              </div>
              <div class="alexa-evidence-col">
                <div class="alexa-col-title">Potential Implications (Inferred)</div>
                <ul class="alexa-col-list">
                  ${impList}
                </ul>
              </div>
            </div>

            <!-- Defensive Actions -->
            <div class="alexa-actions-box">
              <div class="alexa-actions-title">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                Recommended Incident Response Actions:
              </div>
              <ul class="alexa-actions-list">
                ${actionsList}
              </ul>
            </div>

            <div class="alexa-card-footer">
              <span>Model: ${escapeHtml(sr.model_name || 'LogisticRegression')} (${escapeHtml(sr.model_version || '1.0.0')})</span>
              <span>Provider: ${escapeHtml(sr.provider_used || 'rule_based_nlp_engine')}</span>
              <span>MCP Tool: trustlens_inspect_message</span>
            </div>
          </div>
        `;
      }

      // Suggested follow-up prompt chips
      let chipsHtml = '';
      if (data.suggested_prompts && data.suggested_prompts.length > 0) {
        chipsHtml = `<div class="alexa-chips-wrap">` +
          data.suggested_prompts.map(p =>
            `<button type="button" class="alexa-chip" data-prompt="${escapeHtml(p)}">${escapeHtml(p)} &rarr;</button>`
          ).join('') +
          `</div>`;
      }

      const formattedVoiceText = formatMarkdownToHtml(data.conversational_response);

      assistantMsg.innerHTML = `
        <div class="alexa-avatar-sm">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
        </div>
        <div class="alexa-bubble">
          <div class="alexa-sender-tag">
            <span>Alexa+ Assistant &bull; TrustLens AI Agent Skill</span>
            <span class="alexa-tool-badge">${toolBadgeText}</span>
          </div>
          <div class="alexa-spoken-text">
            ${formattedVoiceText}
          </div>
          ${scanCardHtml}
          ${chipsHtml}
        </div>
      `;

      elements.alexaChatFeed.appendChild(assistantMsg);
      elements.alexaChatFeed.scrollTop = elements.alexaChatFeed.scrollHeight;

    } catch (err) {
      if (elements.alexaThinkingIndicator) {
        elements.alexaThinkingIndicator.classList.add('hidden');
      }

      const errorMsg = document.createElement('div');
      errorMsg.className = 'alexa-msg alexa-msg-assistant';
      errorMsg.innerHTML = `
        <div class="alexa-avatar-sm">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
        </div>
        <div class="alexa-bubble" style="border-color:var(--risk-high-border);background:#FEF2F2;">
          <div class="alexa-sender-tag" style="color:var(--risk-high-text);">
            <span>Alexa+ Assistant &bull; System Communication</span>
            <span class="alexa-tool-badge" style="color:var(--risk-high-text);border-color:var(--risk-high-border);">Error</span>
          </div>
          <div class="alexa-spoken-text" style="color:var(--risk-high-text);">
            I encountered an issue connecting to the investigation backend: ${escapeHtml(err.message)}.
            The local ML inference pipeline remains online. Please try asking again or click a sample scenario.
          </div>
          <div class="alexa-chips-wrap">
            <button type="button" class="alexa-chip" data-prompt="Check Chase bank alert sample">Check Chase bank alert sample &rarr;</button>
            <button type="button" class="alexa-chip" data-prompt="Check doctor appointment sample">Check doctor appointment sample &rarr;</button>
          </div>
        </div>
      `;
      elements.alexaChatFeed.appendChild(errorMsg);
      elements.alexaChatFeed.scrollTop = elements.alexaChatFeed.scrollHeight;
      showToast(`Alexa+ Assistant error: ${err.message}`, 'error');
    }
  }

})();

