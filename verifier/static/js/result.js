(() => {
  /* -------------------------------
     SAFETY CHECK
  -------------------------------- */
  const jobId = localStorage.getItem("jobId");

  if (!jobId) {
    alert("No verification job found. Redirecting to upload page.");
    window.location.href = "/upload/";
    return;
  }

  /* -------------------------------
     DOM ELEMENTS
  -------------------------------- */
  const jobIdEl = document.getElementById("jobId");
  const processedAtEl = document.getElementById("processedAt");
  const resultsTable = document.getElementById("resultsTable");
  const exportBtn = document.getElementById("exportBtn");
  const newBtn = document.getElementById("newBtn");
  const searchInput = document.getElementById("searchInput");
  const filterButtons = document.querySelectorAll(".filter-btn");

  const totalEl = document.getElementById("totalCount");
  const validEl = document.getElementById("validCount");
  const invalidEl = document.getElementById("invalidCount");
  const disposableEl = document.getElementById("disposableCount");
  const catchallEl = document.getElementById("catchallCount");
  const unknownEl = document.getElementById("unknownCount");

  /* -------------------------------
     STATE
  -------------------------------- */
  let allResults = [];
  let activeFilter = "all";

  /* -------------------------------
     INITIAL META
  -------------------------------- */
  if(jobIdEl) jobIdEl.textContent = jobId;
  if(processedAtEl) processedAtEl.textContent = new Date().toLocaleString();

  /* -------------------------------
     LOAD RESULTS
  -------------------------------- */
  async function loadResults() {
    try {
      const res = await fetch(`/api/jobs/${jobId}/results/`);

      if (!res.ok) throw new Error("Backend not responding");

      const data = await res.json();

      // Handle DRF Pagination (data.results) vs Raw Array
      const resultsArray = data.results || data; 

      if (Array.isArray(resultsArray)) {
          allResults = resultsArray;
      } else {
          allResults = [];
      }

      // 1. ENABLE SUMMARY UPDATES
      updateSummary(allResults);
      renderResults();
    } catch (err) {
      showBackendError();
      console.error(err);
    }
  }

  /* -------------------------------
     RENDER PIPELINE
  -------------------------------- */
  function renderResults() {
    if(!resultsTable) return;
    resultsTable.innerHTML = "";
    const query = searchInput ? searchInput.value.toLowerCase() : "";

    const filteredResults = allResults.filter((item) => {
      const status = item.status ? item.status.toLowerCase() : "unknown";
      const statusMatch = activeFilter === "all" || status === activeFilter;
      const searchMatch =
        (item.email && item.email.toLowerCase().includes(query)) ||
        status.includes(query) ||
        (item.reason && item.reason.toLowerCase().includes(query));

      return statusMatch && searchMatch;
    });

    if (filteredResults.length === 0) {
      resultsTable.innerHTML = `<tr><td colspan="4" class="p-6 text-center text-slate-500">No results found.</td></tr>`;
      return;
    }

    filteredResults.forEach((item) => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-indigo-50 transition border-b border-slate-100";
      
      const statusHtml = formatStatus(item.status);
      
      let timeStr = "-";
      if (item.verified_at) {
          timeStr = new Date(item.verified_at).toLocaleTimeString();
      }
      
      tr.innerHTML = `
        <td class="p-4 font-medium text-slate-700">${escapeHTML(item.email)}</td>
        <td class="p-4 font-bold">${statusHtml}</td>
        <td class="p-4 text-slate-600 text-sm">${escapeHTML(item.reason || '-')}</td>
        <td class="p-4 text-right font-mono text-xs text-slate-400">${escapeHTML(timeStr)}</td>
      `;
      resultsTable.appendChild(tr);
    });
  }

  function updateSummary(data) {
    // 3. UPDATE COUNTERS
    if(totalEl) totalEl.textContent = data.length;
    if(validEl) validEl.textContent = data.filter(i => i.status.toLowerCase() === 'valid').length;
    if(invalidEl) invalidEl.textContent = data.filter(i => i.status.toLowerCase() === 'invalid').length;
    
    // Map 'Risky' -> Disposable/Catch-all UI buckets
    const riskyCount = data.filter(i => i.status.toLowerCase() === 'risky').length;
    if(disposableEl) disposableEl.textContent = riskyCount; 
    
    // Optional: If you want to separate catch-all later, add logic here.
    if(catchallEl) catchallEl.textContent = "0"; 
    
    if(unknownEl) unknownEl.textContent = data.filter(i => i.status.toLowerCase() === 'unknown').length;
  }

  /* -------------------------------
     HANDLERS
  -------------------------------- */
  if(exportBtn) {
      exportBtn.addEventListener("click", () => {
        window.location.href = `/api/jobs/${jobId}/download/`;
      });
  }

  if(newBtn) {
      newBtn.addEventListener("click", () => {
        localStorage.removeItem("jobId");
        window.location.href = "/upload/";
      });
  }
  
  if (searchInput) searchInput.addEventListener("input", renderResults);

  filterButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      filterButtons.forEach((b) => b.classList.remove("active", "bg-indigo-100", "text-indigo-700"));
      btn.classList.add("active", "bg-indigo-100", "text-indigo-700");
      activeFilter = btn.dataset.status.toLowerCase();
      renderResults();
    });
  });

  /* -------------------------------
     HELPERS
  -------------------------------- */
  function showBackendError() {
    if(resultsTable) resultsTable.innerHTML = `<tr><td colspan="4" class="p-6 text-center text-red-600 font-bold">Failed to load results.</td></tr>`;
  }

  function formatStatus(status) {
    if(!status) return "Unknown";
    const s = status.toLowerCase();
    let color = "gray";
    if (s === 'valid') color = "green";
    if (s === 'invalid') color = "red";
    if (s === 'risky') color = "orange";
    
    return `<span class="px-2 py-1 rounded-full bg-${color}-100 text-${color}-700 text-xs uppercase tracking-wide">${status}</span>`;
  }

  function escapeHTML(str) {
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  loadResults();
})();