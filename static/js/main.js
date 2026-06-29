// =============================================================================
// Password Guardian Pro — main.js
// =============================================================================
// Single-page application controller. Handles all UI interactions, API calls,
// chart rendering, and state management for the four-tab interface.
//
// Architecture:
//   - Module pattern via an IIFE — no global pollution
//   - Event delegation where possible
//   - All API calls centralised in the Api module
//   - UI updates centralised in the UI module
//   - Charts managed in the Charts module
// =============================================================================

(() => {
  'use strict';

  // ---------------------------------------------------------------------------
  // Api — centralised fetch wrapper
  // ---------------------------------------------------------------------------

  const Api = {
    /**
     * POST /api/analyze
     * @param {string} password
     * @returns {Promise<object>}
     */
    async analyze(password) {
      return Api._post('/api/analyze', { password, save: true });
    },

    /**
     * POST /api/generate
     * @param {object} options
     * @returns {Promise<object>}
     */
    async generate(options) {
      return Api._post('/api/generate', options);
    },

    /**
     * GET /api/history
     * @param {number} limit
     * @returns {Promise<object>}
     */
    async history(limit = 20) {
      const res = await fetch(`/api/history?limit=${limit}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },

    /**
     * GET /api/stats
     * @returns {Promise<object>}
     */
    async stats() {
      const res = await fetch('/api/stats');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },

    /**
     * POST /api/clear
     * @returns {Promise<object>}
     */
    async clear() {
      return Api._post('/api/clear', {});
    },

    /**
     * Internal POST helper with JSON body.
     * @param {string} url
     * @param {object} body
     * @returns {Promise<object>}
     */
    async _post(url, body) {
      const res = await fetch(url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    },
  };

  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------

  const State = {
    currentTab:      'analyzer',
    lastReport:      null,
    lastGenerated:   null,
    generatorMode:   'random',
    analysisDebounce: null,
    pieChart:        null,
    barChart:        null,
  };

  // ---------------------------------------------------------------------------
  // DOM references — queried once at init
  // ---------------------------------------------------------------------------

  const DOM = {};

  function cacheDom() {
    // Navbar
    DOM.navBtns        = document.querySelectorAll('.nav-btn');
    DOM.themeToggle    = document.getElementById('themeToggle');
    DOM.themeIcon      = document.querySelector('.theme-icon');

    // Analyser
    DOM.passwordInput  = document.getElementById('passwordInput');
    DOM.toggleVis      = document.getElementById('toggleVisibility');
    DOM.analyzeBtn     = document.getElementById('analyzeBtn');
    DOM.clearBtn       = document.getElementById('clearBtn');
    DOM.meterFill      = document.getElementById('meterFill');
    DOM.strengthLabel  = document.getElementById('strengthLabel');
    DOM.strengthScore  = document.getElementById('strengthScore');
    DOM.resultsGrid    = document.getElementById('resultsGrid');

    // Score ring
    DOM.scoreRingFill  = document.getElementById('scoreRingFill');
    DOM.scoreNumber    = document.getElementById('scoreNumber');
    DOM.scoreGrade     = document.getElementById('scoreGrade');
    DOM.scoreStrength  = document.getElementById('scoreStrength');

    // Crack time
    DOM.crackSummary   = document.getElementById('crackSummary');
    DOM.ctOnlineThrot  = document.getElementById('ct-online-throttled');
    DOM.ctOnlineUnthrot= document.getElementById('ct-online-unthrottled');
    DOM.ctOfflineSlow  = document.getElementById('ct-offline-slow');
    DOM.ctOfflineFast  = document.getElementById('ct-offline-fast');
    DOM.ctOfflineGpu   = document.getElementById('ct-offline-gpu');

    // Checks
    DOM.chkLength      = document.getElementById('chk-length');
    DOM.chkLengthVal   = document.getElementById('chk-length-val');
    DOM.chkUppercase   = document.getElementById('chk-uppercase');
    DOM.chkLowercase   = document.getElementById('chk-lowercase');
    DOM.chkDigits      = document.getElementById('chk-digits');
    DOM.chkSymbols     = document.getElementById('chk-symbols');
    DOM.chkEntropy     = document.getElementById('chk-entropy');
    DOM.chkEntropyVal  = document.getElementById('chk-entropy-val');
    DOM.chkRepeats     = document.getElementById('chk-repeats');
    DOM.chkSequences   = document.getElementById('chk-sequences');
    DOM.chkKeyboard    = document.getElementById('chk-keyboard');
    DOM.chkBreached    = document.getElementById('chk-breached');

    // Suggestions
    DOM.suggestionsList = document.getElementById('suggestionsList');

    // Entropy
    DOM.rawEntropy     = document.getElementById('rawEntropy');
    DOM.trueEntropy    = document.getElementById('trueEntropy');
    DOM.zxcvbnScore    = document.getElementById('zxcvbnScore');
    DOM.charPool       = document.getElementById('charPool');
    DOM.entropyBar     = document.getElementById('entropyBar');

    // Hash
    DOM.hashDisplay    = document.getElementById('hashDisplay');

    // Generator
    DOM.modeBtns       = document.querySelectorAll('.mode-btn');
    DOM.lengthSlider   = document.getElementById('lengthSlider');
    DOM.lengthDisplay  = document.getElementById('lengthDisplay');
    DOM.wordCountSlider= document.getElementById('wordCountSlider');
    DOM.wordCountDisplay=document.getElementById('wordCountDisplay');
    DOM.lengthGroup    = document.getElementById('lengthGroup');
    DOM.wordCountGroup = document.getElementById('wordCountGroup');
    DOM.charClassGroup = document.getElementById('charClassGroup');
    DOM.genUppercase   = document.getElementById('genUppercase');
    DOM.genLowercase   = document.getElementById('genLowercase');
    DOM.genDigits      = document.getElementById('genDigits');
    DOM.genSymbols     = document.getElementById('genSymbols');
    DOM.genAvoidAmbig  = document.getElementById('genAvoidAmbiguous');
    DOM.generateBtn    = document.getElementById('generateBtn');
    DOM.genResultBox   = document.getElementById('genResultBox');
    DOM.genActions     = document.getElementById('genActions');
    DOM.genMeta        = document.getElementById('genMeta');
    DOM.copyBtn        = document.getElementById('copyBtn');
    DOM.analyzeGenBtn  = document.getElementById('analyzeGenBtn');
    DOM.regenBtn       = document.getElementById('regenBtn');
    DOM.genEntropy     = document.getElementById('genEntropy');
    DOM.genPoolSize    = document.getElementById('genPoolSize');
    DOM.genLength      = document.getElementById('genLength');

    // Dashboard
    DOM.statTotal      = document.getElementById('stat-total');
    DOM.statAvg        = document.getElementById('stat-avg');
    DOM.statStrongPct  = document.getElementById('stat-strong-pct');
    DOM.statWeakPct    = document.getElementById('stat-weak-pct');
    DOM.historyBody    = document.getElementById('historyTableBody');
    DOM.refreshHistory = document.getElementById('refreshHistory');
    DOM.clearHistoryBtn= document.getElementById('clearHistoryBtn');

    // Utility
    DOM.toast          = document.getElementById('toast');
    DOM.loadingOverlay = document.getElementById('loadingOverlay');
  }

  // ---------------------------------------------------------------------------
  // UI helpers
  // ---------------------------------------------------------------------------

  const UI = {

    /** Show/hide the loading overlay */
    setLoading(visible) {
      DOM.loadingOverlay.classList.toggle('hidden', !visible);
    },

    /**
     * Show a toast notification.
     * @param {string} message
     * @param {'success'|'error'|'info'} type
     * @param {number} duration ms
     */
    toast(message, type = 'info', duration = 2800) {
      const el = DOM.toast;
      el.textContent = message;
      el.className   = `toast toast-${type} show`;
      clearTimeout(el._timer);
      el._timer = setTimeout(() => {
        el.classList.remove('show');
      }, duration);
    },

    /**
     * Update the strength meter bar and label.
     * @param {number} score  0–100
     * @param {string} strength
     * @param {string} color  CSS hex
     */
    updateMeter(score, strength, color) {
      DOM.meterFill.style.width           = `${score}%`;
      DOM.meterFill.style.backgroundColor = color;
      DOM.strengthLabel.textContent       = strength;
      DOM.strengthLabel.style.color       = color;
      DOM.strengthScore.textContent       = `${score}/100`;
    },

    /**
     * Animate the SVG score ring.
     * @param {number} score  0–100
     * @param {string} color  CSS hex
     */
    updateScoreRing(score, color) {
      const circumference = 314; // 2 * π * r=50
      const offset        = circumference - (score / 100) * circumference;
      DOM.scoreRingFill.style.strokeDashoffset = offset;
      DOM.scoreRingFill.style.stroke           = color;
      DOM.scoreNumber.textContent              = score;
    },

    /**
     * Apply pass/fail styling to a check item.
     * @param {HTMLElement} el
     * @param {boolean}     passed
     * @param {string}      passIcon
     * @param {string}      failIcon
     */
    setCheck(el, passed, passIcon = '✓', failIcon = '✗') {
      el.classList.toggle('pass', passed);
      el.classList.toggle('fail', !passed);
      el.querySelector('.check-icon').textContent = passed ? passIcon : failIcon;
    },

    /** Render suggestions list */
    renderSuggestions(suggestions) {
      DOM.suggestionsList.innerHTML = '';
      suggestions.forEach(s => {
        const li = document.createElement('li');
        li.textContent = s;
        if (s.startsWith('✅')) li.classList.add('suggestion-good');
        DOM.suggestionsList.appendChild(li);
      });
    },

    /** Render history table rows */
    renderHistoryTable(records) {
      if (!records || records.length === 0) {
        DOM.historyBody.innerHTML =
          '<tr><td colspan="8" class="table-empty">No analyses recorded yet.</td></tr>';
        return;
      }

      DOM.historyBody.innerHTML = records.map((r, i) => `
        <tr>
          <td>${r.id}</td>
          <td>${UI._formatDate(r.created_at)}</td>
          <td><code>${r.hash}</code></td>
          <td>${r.score}</td>
          <td><span class="badge ${UI._strengthBadgeClass(r.strength)}">${r.strength}</span></td>
          <td>${parseFloat(r.entropy).toFixed(1)} bits</td>
          <td><strong>${r.grade}</strong></td>
          <td>${r.breached ? '⚠️ Yes' : '✅ No'}</td>
        </tr>
      `).join('');
    },

    /** Format ISO timestamp to readable string */
    _formatDate(iso) {
      try {
        return new Date(iso).toLocaleString(undefined, {
          month: 'short', day: 'numeric',
          hour: '2-digit', minute: '2-digit',
        });
      } catch { return iso; }
    },

    /** Map strength string to badge CSS class */
    _strengthBadgeClass(strength) {
      const map = {
        'Very Weak':   'badge-very-weak',
        'Weak':        'badge-weak',
        'Fair':        'badge-fair',
        'Strong':      'badge-strong',
        'Very Strong': 'badge-very-strong',
      };
      return map[strength] || 'badge-fair';
    },
  };

  // ---------------------------------------------------------------------------
  // Charts
  // ---------------------------------------------------------------------------

  const Charts = {

    /** Chart.js default color palette matching CSS tokens */
    _colors: {
      'Very Weak':   '#ef4444',
      'Weak':        '#f97316',
      'Fair':        '#eab308',
      'Strong':      '#22c55e',
      'Very Strong': '#10b981',
    },

    _isDark() {
      return document.body.getAttribute('data-theme') === 'dark';
    },

    _textColor() {
      return this._isDark() ? '#8892b0' : '#4a5380';
    },

    _gridColor() {
      return this._isDark()
        ? 'rgba(99,120,200,0.12)'
        : 'rgba(100,120,220,0.1)';
    },

    /**
     * Render / update the strength pie chart.
     * @param {object} breakdown  { "Weak": 3, "Strong": 7, … }
     */
    renderPie(breakdown) {
      const ctx    = document.getElementById('strengthPieChart');
      const labels = Object.keys(breakdown);
      const data   = Object.values(breakdown);
      const colors = labels.map(l => this._colors[l] || '#6478f0');

      if (State.pieChart) {
        State.pieChart.data.labels           = labels;
        State.pieChart.data.datasets[0].data = data;
        State.pieChart.data.datasets[0].backgroundColor = colors;
        State.pieChart.update('active');
        return;
      }

      State.pieChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data,
            backgroundColor:  colors,
            borderColor:      'transparent',
            borderWidth:      0,
            hoverOffset:      8,
          }],
        },
        options: {
          responsive:          true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'right',
              labels: {
                color:     this._textColor(),
                font:      { size: 11 },
                boxWidth:  12,
                padding:   14,
              },
            },
            tooltip: {
              callbacks: {
                label: ctx => ` ${ctx.label}: ${ctx.raw} passwords`,
              },
            },
          },
        },
      });
    },

    /**
     * Render / update the score distribution bar chart.
     * @param {object} distribution  { "0-19": 2, "20-39": 5, … }
     */
    renderBar(distribution) {
      const ctx    = document.getElementById('scoreBarChart');
      const bands  = ['0-19', '20-39', '40-59', '60-79', '80-100'];
      const data   = bands.map(b => distribution[b] || 0);
      const colors = [
        '#ef4444', '#f97316', '#eab308', '#22c55e', '#10b981',
      ];

      if (State.barChart) {
        State.barChart.data.datasets[0].data = data;
        State.barChart.update('active');
        return;
      }

      State.barChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: bands,
          datasets: [{
            label:           'Passwords',
            data,
            backgroundColor: colors,
            borderRadius:    6,
            borderSkipped:   false,
          }],
        },
        options: {
          responsive:          true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: ctx => ` ${ctx.raw} password${ctx.raw !== 1 ? 's' : ''}`,
              },
            },
          },
          scales: {
            x: {
              grid:  { color: this._gridColor() },
              ticks: { color: this._textColor(), font: { size: 11 } },
            },
            y: {
              grid:  { color: this._gridColor() },
              ticks: { color: this._textColor(), font: { size: 11 }, stepSize: 1 },
              beginAtZero: true,
            },
          },
        },
      });
    },

    /** Destroy and re-render charts (used on theme switch) */
    refresh() {
      if (State.pieChart) { State.pieChart.destroy(); State.pieChart = null; }
      if (State.barChart) { State.barChart.destroy(); State.barChart = null; }
      loadDashboard();
    },
  };

  // ---------------------------------------------------------------------------
  // Analyser logic
  // ---------------------------------------------------------------------------

  /**
   * Run a full password analysis and populate all result cards.
   */
  async function runAnalysis() {
    const password = DOM.passwordInput.value;
    if (!password.trim()) {
      UI.toast('Enter a password to analyse.', 'error');
      return;
    }

    UI.setLoading(true);

    try {
      const report = await Api.analyze(password);
      State.lastReport = report;
      populateResults(report);
      DOM.resultsGrid.classList.remove('hidden');
      DOM.resultsGrid.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (err) {
      UI.toast(`Analysis failed: ${err.message}`, 'error');
    } finally {
      UI.setLoading(false);
    }
  }

  /**
   * Populate all result cards from an analysis report.
   * @param {object} report
   */
  function populateResults(report) {
    const { score, strength, color, checks, suggestions,
            crack_time, entropy, true_entropy, grade,
            zxcvbn_score, hash, breached } = report;

    // Meter & score ring
    UI.updateMeter(score, strength, color);
    UI.updateScoreRing(score, color);
    DOM.scoreGrade.textContent    = grade;
    DOM.scoreGrade.style.color    = color;
    DOM.scoreStrength.textContent = strength;

    // Crack time
    DOM.crackSummary.textContent    = crack_time.summary;
    DOM.crackSummary.style.color    = color;
    DOM.ctOnlineThrot.textContent   = crack_time.online_throttled;
    DOM.ctOnlineUnthrot.textContent = crack_time.online_unthrottled;
    DOM.ctOfflineSlow.textContent   = crack_time.offline_slow;
    DOM.ctOfflineFast.textContent   = crack_time.offline_fast;
    DOM.ctOfflineGpu.textContent    = crack_time.offline_gpu_cluster;

    // Security checks
    DOM.chkLengthVal.textContent = `${checks.length} chars`;
    UI.setCheck(DOM.chkLength,    checks.length_good);
    UI.setCheck(DOM.chkUppercase, checks.has_uppercase);
    UI.setCheck(DOM.chkLowercase, checks.has_lowercase);
    UI.setCheck(DOM.chkDigits,    checks.has_digits);
    UI.setCheck(DOM.chkSymbols,   checks.has_symbols);
    UI.setCheck(DOM.chkRepeats,   !checks.has_repeats);
    UI.setCheck(DOM.chkSequences, !checks.has_sequences);
    UI.setCheck(DOM.chkKeyboard,  !checks.has_keyboard_walk);
    UI.setCheck(DOM.chkBreached,  !breached);

    // Entropy display
    const entropyPct = Math.min(100, (true_entropy / 128) * 100);
    DOM.chkEntropyVal.textContent = `${true_entropy} bits`;
    UI.setCheck(DOM.chkEntropy, true_entropy >= 60);
    DOM.rawEntropy.textContent   = `${entropy} bits`;
    DOM.trueEntropy.textContent  = `${true_entropy} bits`;
    DOM.zxcvbnScore.textContent  = `${zxcvbn_score} / 4`;
    DOM.entropyBar.style.width   = `${entropyPct}%`;

    // Character pool size (derived from checks)
    let pool = 0;
    if (checks.has_lowercase) pool += 26;
    if (checks.has_uppercase) pool += 26;
    if (checks.has_digits)    pool += 10;
    if (checks.has_symbols)   pool += 32;
    DOM.charPool.textContent = `${pool} characters`;

    // Suggestions
    UI.renderSuggestions(suggestions);

    // Hash
    DOM.hashDisplay.textContent = hash;
  }

  /**
   * Live meter update as user types (debounced, no API call).
   * Gives instant visual feedback without hammering the server.
   */
  function liveMetterUpdate() {
    const pw  = DOM.passwordInput.value;
    if (!pw) {
      DOM.meterFill.style.width = '0%';
      DOM.strengthLabel.textContent = '—';
      DOM.strengthScore.textContent = '';
      return;
    }

    // Quick local score — length + char class presence only
    let quick = 0;
    if (pw.length >= 8)  quick += 20;
    if (pw.length >= 12) quick += 10;
    if (pw.length >= 16) quick += 10;
    if (/[A-Z]/.test(pw)) quick += 15;
    if (/[a-z]/.test(pw)) quick += 15;
    if (/[0-9]/.test(pw)) quick += 15;
    if (/[^A-Za-z0-9]/.test(pw)) quick += 15;
    quick = Math.min(100, quick);

    const { label, color } = quickStrengthLabel(quick);
    UI.updateMeter(quick, label, color);
  }

  function quickStrengthLabel(score) {
    if (score < 20) return { label: 'Very Weak',   color: '#ef4444' };
    if (score < 40) return { label: 'Weak',        color: '#f97316' };
    if (score < 60) return { label: 'Fair',        color: '#eab308' };
    if (score < 80) return { label: 'Strong',      color: '#22c55e' };
    return              { label: 'Very Strong', color: '#10b981' };
  }

  // ---------------------------------------------------------------------------
  // Generator logic
  // ---------------------------------------------------------------------------

  async function runGenerate() {
    const mode = State.generatorMode;
    const options = { mode };

    if (mode === 'random' || mode === 'pronounceable') {
      options.length          = parseInt(DOM.lengthSlider.value);
      options.use_uppercase   = DOM.genUppercase.checked;
      options.use_lowercase   = DOM.genLowercase.checked;
      options.use_digits      = DOM.genDigits.checked;
      options.use_symbols     = DOM.genSymbols.checked;
      options.avoid_ambiguous = DOM.genAvoidAmbig.checked;
      options.pronounceable   = (mode === 'pronounceable');
    }

    if (mode === 'passphrase') {
      options.word_count    = parseInt(DOM.wordCountSlider.value);
      options.separator     = '-';
      options.capitalise    = true;
      options.append_number = true;
    }

    if (mode === 'pin') {
      options.length = parseInt(DOM.lengthSlider.value);
    }

    try {
      DOM.generateBtn.disabled = true;
      DOM.generateBtn.textContent = 'Generating…';

      const result = await Api.generate(options);
      State.lastGenerated = result;

      const pw = result.password || result.passphrase || result.pin;

      DOM.genResultBox.textContent = pw;
      DOM.genResultBox.classList.add('has-value');
      DOM.genResultBox.querySelector
        && DOM.genResultBox.querySelector('.gen-placeholder')?.remove();

      DOM.genActions.classList.remove('hidden');
      DOM.genMeta.classList.remove('hidden');

      DOM.genEntropy.textContent  = result.entropy ? `${result.entropy} bits` : '—';
      DOM.genPoolSize.textContent = result.pool_size ? `${result.pool_size} chars` : '—';
      DOM.genLength.textContent   = result.length || pw.length;

    } catch (err) {
      UI.toast(`Generation failed: ${err.message}`, 'error');
    } finally {
      DOM.generateBtn.disabled    = false;
      DOM.generateBtn.textContent = 'Generate Password';
    }
  }

  // ---------------------------------------------------------------------------
  // Dashboard logic
  // ---------------------------------------------------------------------------

  async function loadDashboard() {
    try {
      const [statsData, historyData] = await Promise.all([
        Api.stats(),
        Api.history(20),
      ]);

      // Stat tiles
      DOM.statTotal.textContent     = statsData.total_checked;
      DOM.statAvg.textContent       = statsData.average_score || '—';
      DOM.statStrongPct.textContent = statsData.total_checked
        ? `${statsData.strong_percent}%` : '—';
      DOM.statWeakPct.textContent   = statsData.total_checked
        ? `${statsData.weak_percent}%` : '—';

      // Charts
      if (statsData.total_checked > 0) {
        Charts.renderPie(statsData.strength_breakdown || {});
        Charts.renderBar(statsData.score_distribution || {});
      }

      // History table
      UI.renderHistoryTable(historyData.records);

    } catch (err) {
      UI.toast(`Dashboard error: ${err.message}`, 'error');
    }
  }

  // ---------------------------------------------------------------------------
  // Tab navigation
  // ---------------------------------------------------------------------------

  function switchTab(tabName) {
    State.currentTab = tabName;

    // Update nav buttons
    DOM.navBtns.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tabName);
    });

    // Update panels
    document.querySelectorAll('.tab-panel').forEach(panel => {
      panel.classList.toggle('active', panel.id === `tab-${tabName}`);
    });

    // Lazy-load dashboard data when switching to it
    if (tabName === 'dashboard') {
      loadDashboard();
    }
  }

  // ---------------------------------------------------------------------------
  // Theme toggle
  // ---------------------------------------------------------------------------

  function toggleTheme() {
    const body    = document.body;
    const isDark  = body.getAttribute('data-theme') === 'dark';
    const newTheme = isDark ? 'light' : 'dark';

    body.setAttribute('data-theme', newTheme);
    DOM.themeIcon.textContent = isDark ? '☀️' : '🌙';
    localStorage.setItem('pgp-theme', newTheme);

    // Re-render charts with new theme colors
    Charts.refresh();
  }

  function loadSavedTheme() {
    const saved = localStorage.getItem('pgp-theme');
    if (saved) {
      document.body.setAttribute('data-theme', saved);
      DOM.themeIcon.textContent = saved === 'dark' ? '🌙' : '☀️';
    }
  }

  // ---------------------------------------------------------------------------
  // Generator mode switching
  // ---------------------------------------------------------------------------

  function setGeneratorMode(mode) {
    State.generatorMode = mode;

    DOM.modeBtns.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.mode === mode);
    });

    const isPassphrase = mode === 'passphrase';
    const isPin        = mode === 'pin';
    const isRandom     = mode === 'random' || mode === 'pronounceable';

    DOM.wordCountGroup.classList.toggle('hidden', !isPassphrase);
    DOM.charClassGroup.classList.toggle('hidden',  isPassphrase || isPin);
    DOM.lengthGroup.classList.toggle('hidden',     isPassphrase);

    // Adjust slider for PIN mode
    if (isPin) {
      DOM.lengthSlider.min   = '4';
      DOM.lengthSlider.max   = '12';
      DOM.lengthSlider.value = '6';
      DOM.lengthDisplay.textContent = '6';
    } else {
      DOM.lengthSlider.min   = '8';
      DOM.lengthSlider.max   = '64';
      if (parseInt(DOM.lengthSlider.value) < 8) DOM.lengthSlider.value = '16';
      DOM.lengthDisplay.textContent = DOM.lengthSlider.value;
    }
  }

  // ---------------------------------------------------------------------------
  // Copy to clipboard
  // ---------------------------------------------------------------------------

  async function copyToClipboard(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        // Fallback for non-HTTPS
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity  = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      UI.toast('📋 Copied to clipboard!', 'success');
    } catch {
      UI.toast('Copy failed — select manually.', 'error');
    }
  }

  // ---------------------------------------------------------------------------
  // Event binding
  // ---------------------------------------------------------------------------

  function bindEvents() {

    // --- Tab navigation ---
    DOM.navBtns.forEach(btn => {
      btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    // --- Theme toggle ---
    DOM.themeToggle.addEventListener('click', toggleTheme);

    // --- Password input: live meter + Enter to analyse ---
    DOM.passwordInput.addEventListener('input', () => {
      liveMetterUpdate();
    });

    DOM.passwordInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') runAnalysis();
    });

    // --- Analyse button ---
    DOM.analyzeBtn.addEventListener('click', runAnalysis);

    // --- Clear button ---
    DOM.clearBtn.addEventListener('click', () => {
      DOM.passwordInput.value       = '';
      DOM.meterFill.style.width     = '0%';
      DOM.strengthLabel.textContent = '—';
      DOM.strengthScore.textContent = '';
      DOM.resultsGrid.classList.add('hidden');
      DOM.passwordInput.focus();
    });

    // --- Toggle password visibility ---
    DOM.toggleVis.addEventListener('click', () => {
      const isPassword = DOM.passwordInput.type === 'password';
      DOM.passwordInput.type = isPassword ? 'text' : 'password';
      DOM.toggleVis.querySelector('span').textContent = isPassword ? '🙈' : '👁';
    });

    // --- Generator: mode buttons ---
    DOM.modeBtns.forEach(btn => {
      btn.addEventListener('click', () => setGeneratorMode(btn.dataset.mode));
    });

    // --- Generator: length slider ---
    DOM.lengthSlider.addEventListener('input', () => {
      DOM.lengthDisplay.textContent = DOM.lengthSlider.value;
    });

    // --- Generator: word count slider ---
    DOM.wordCountSlider.addEventListener('input', () => {
      DOM.wordCountDisplay.textContent = DOM.wordCountSlider.value;
    });

    // --- Generate button ---
    DOM.generateBtn.addEventListener('click', runGenerate);

    // --- Copy generated password ---
    DOM.copyBtn.addEventListener('click', () => {
      const result = State.lastGenerated;
      if (!result) return;
      const pw = result.password || result.passphrase || result.pin || '';
      copyToClipboard(pw);
    });

    // --- Analyse generated password (switch tab + prefill) ---
    DOM.analyzeGenBtn.addEventListener('click', () => {
      const result = State.lastGenerated;
      if (!result) return;
      const pw = result.password || result.passphrase || result.pin || '';
      DOM.passwordInput.value = pw;
      switchTab('analyzer');
      liveMetterUpdate();
      // Small delay so tab transition completes before scrolling
      setTimeout(runAnalysis, 150);
    });

    // --- Regenerate ---
    DOM.regenBtn.addEventListener('click', runGenerate);

    // --- Dashboard: refresh ---
    DOM.refreshHistory.addEventListener('click', () => {
      loadDashboard();
      UI.toast('Dashboard refreshed.', 'info');
    });

    // --- Dashboard: clear history ---
    DOM.clearHistoryBtn.addEventListener('click', async () => {
      if (!confirm('Delete all analysis history? This cannot be undone.')) return;
      try {
        const res = await Api.clear();
        UI.toast(`Deleted ${res.deleted} records.`, 'success');
        loadDashboard();
      } catch (err) {
        UI.toast(`Clear failed: ${err.message}`, 'error');
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Initialisation
  // ---------------------------------------------------------------------------

  function init() {
    cacheDom();
    loadSavedTheme();
    bindEvents();

    // Focus the password input on load
    DOM.passwordInput.focus();

    console.info(
      '%c🛡️ Password Guardian Pro',
      'font-size:16px; font-weight:bold; color:#6478f0;',
      '\nReady. All modules loaded.'
    );
  }

  // Boot
  document.addEventListener('DOMContentLoaded', init);

})();
