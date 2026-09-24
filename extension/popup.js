document.addEventListener('DOMContentLoaded', async () => {
  const urlDisplay = document.getElementById('url-display');
  const loading = document.getElementById('loading');
  const errorContainer = document.getElementById('error');
  const errorMessage = document.getElementById('error-message');
  const resultContainer = document.getElementById('result');
  const scoreCard = document.getElementById('score-card');
  const settingsBtn = document.getElementById('settings-btn');
  const settingsDiv = document.getElementById('settings');
  const saveSettingsBtn = document.getElementById('save-settings');

  // Elements to populate
  const elClassification = document.getElementById('classification');
  const elScore = document.getElementById('risk-score');
  const elConfidence = document.getElementById('confidence');
  const elIndicatorList = document.getElementById('indicator-list');
  const elIntelBox = document.getElementById('threat-intel-box');
  const elIntelList = document.getElementById('intel-list');

  // Load config
  let apiUrl = 'http://127.0.0.1:5000/api/v1/analyze/url';
  let apiToken = '';
  
  try {
    const config = await chrome.storage.local.get(['apiUrl', 'apiToken']);
    if (config.apiUrl) apiUrl = config.apiUrl;
    if (config.apiToken) apiToken = config.apiToken;
  } catch (e) {
    // defaults
  }
  
  document.getElementById('api-url').value = apiUrl;
  document.getElementById('api-token').value = apiToken;

  settingsBtn.addEventListener('click', () => {
    settingsDiv.classList.toggle('hidden');
  });

  saveSettingsBtn.addEventListener('click', async () => {
    apiUrl = document.getElementById('api-url').value;
    apiToken = document.getElementById('api-token').value;
    await chrome.storage.local.set({ apiUrl, apiToken });
    settingsDiv.classList.add('hidden');
    analyzeUrl(); // retry
  });

  async function getCurrentTabUrl() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      return tabs[0]?.url || null;
    } catch (e) {
      return null;
    }
  }

  async function analyzeUrl() {
    loading.classList.remove('hidden');
    errorContainer.classList.add('hidden');
    resultContainer.classList.add('hidden');

    const url = await getCurrentTabUrl();
    if (!url || !url.startsWith('http')) {
      urlDisplay.textContent = 'Not a valid HTTP/HTTPS page.';
      loading.classList.add('hidden');
      return;
    }

    urlDisplay.textContent = url.length > 50 ? url.substring(0, 47) + '...' : url;

    try {
      const headers = { 'Content-Type': 'application/json' };
      if (apiToken) {
        headers['Authorization'] = 'Bearer ' + apiToken;
      }

      const res = await fetch(apiUrl, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ url: url })
      });

      if (!res.ok) {
        if (res.status === 401) throw new Error("Unauthorized (Check API Token)");
        if (res.status === 429) throw new Error("Rate limit exceeded.");
        throw new Error(`Server returned ${res.status}`);
      }

      const data = await res.json();
      if (data.status !== "success") {
        throw new Error(data.message || "Analysis failed.");
      }

      displayResult(data.data);

    } catch (error) {
      loading.classList.add('hidden');
      errorContainer.classList.remove('hidden');
      errorMessage.textContent = error.message;
    }
  }

  function displayResult(data) {
    loading.classList.add('hidden');
    resultContainer.classList.remove('hidden');

    // Populate Score Card
    const classification = data.prediction || "legitimate";
    elClassification.textContent = classification;
    elScore.textContent = data.risk_score || 0;
    elConfidence.textContent = ((data.confidence || 0) * 100).toFixed(1);

    // Apply color theme
    scoreCard.className = 'score-card status-' + classification;

    // Populate Indicators
    elIndicatorList.innerHTML = '';
    const indicators = data.contributing_signals || [];
    if (indicators.length === 0) {
      elIndicatorList.innerHTML = '<li style="border-left-color: #94a3b8">No significant anomalies detected.</li>';
    } else {
      indicators.forEach(sig => {
        const li = document.createElement('li');
        li.textContent = sig;
        elIndicatorList.appendChild(li);
      });
    }

    // Threat Intel
    const intel = data.reputation_sources || [];
    if (intel.length > 0) {
      elIntelBox.style.display = 'block';
      elIntelList.innerHTML = '';
      intel.forEach(src => {
        const li = document.createElement('li');
        const color = src.is_malicious ? '#ef4444' : '#10b981';
        li.style.borderLeftColor = color;
        li.innerHTML = `<strong>${src.provider}</strong>: <span style="color:${color}">${src.is_malicious ? 'Malicious' : 'Clean'}</span>`;
        elIntelList.appendChild(li);
      });
    } else {
      elIntelBox.style.display = 'none';
    }
  }

  // Start analysis
  analyzeUrl();
});
