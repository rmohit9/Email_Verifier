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

  // Summary Counts
  const totalEl = document.getElementById("totalCount");
  const validEl = document.getElementById("validCount");
  const invalidEl = document.getElementById("invalidCount");
  const disposableEl = document.getElementById("disposableCount");
  const catchallEl = document.getElementById("catchallCount");
  const unknownEl = document.getElementById("unknownCount");

  // Pagination
  const prevBtn = document.getElementById("prevBtn");
  const nextBtn = document.getElementById("nextBtn");
  const pageInfo = document.getElementById("pageInfo");

  /* -------------------------------
     STATE
  -------------------------------- */
  let currentResults = [];
  let nextUrl = null;
  let prevUrl = null;
  let activeFilter = "all";

  /* -------------------------------
     INITIAL META
  -------------------------------- */
  if(jobIdEl) jobIdEl.textContent = jobId;
  if(processedAtEl) processedAtEl.textContent = new Date().toLocaleString();

  /* -------------------------------
     1. LOAD SUMMARY STATS (The "Correct Numbers")
  -------------------------------- */
  async function loadJobStats() {
    try {
      const res = await fetch(`/api/jobs/${jobId}/`);
      if (!res.ok) throw new Error("Failed to load job stats");
      const job = await res.json();

      if(totalEl) totalEl.textContent = job.total_count || 0;
      if(validEl) validEl.textContent = job.valid_count || 0;
      if(invalidEl) invalidEl.textContent = job.invalid_count || 0;
      
      // Now using the field added to the serializer
      if(disposableEl) disposableEl.textContent = job.disposable_count || 0;
      
      if(catchallEl) catchallEl.textContent = "0"; // Add backend logic if needed
      if(unknownEl) unknownEl.textContent = "0";   // Usually 0 after completion
      
    } catch (err) {
      console.error("Stats Error:", err);
    }
  }

  /* -------------------------------
     2. LOAD PAGINATED RESULTS
  -------------------------------- */
  async function loadResultsPage(url) {
    if (!url) return;
    
    // Add filter param if needed
    const fetchUrl = new URL(url, window.location.origin);
    if (activeFilter !== 'all') {
        fetchUrl.searchParams.set('status', activeFilter);
    }

    // 1. Calculate Serial Number Offset
    // If URL has ?page=2, start at 21. Default to 1.
    const pageParam = fetchUrl.searchParams.get("page");
    const currentPage = pageParam ? parseInt(pageParam) : 1;
    const pageSize = 20; // Matches DRF default
    const startSerial = (currentPage - 1) * pageSize + 1;

    try {
      if(prevBtn) prevBtn.disabled = true;
      if(nextBtn) nextBtn.disabled = true;
      if(resultsTable) resultsTable.innerHTML = `<tr><td colspan="5" class="p-6 text-center text-slate-400">Loading...</td></tr>`; // Changed colspan to 5

      const res = await fetch(fetchUrl);
      if (!res.ok) throw new Error("Backend not responding");

      const data = await res.json();

      currentResults = data.results || [];
      nextUrl = data.next;
      prevUrl = data.previous;
      const totalCount = data.count || 0;

      if(prevBtn) prevBtn.disabled = !prevUrl;
      if(nextBtn) nextBtn.disabled = !nextUrl;
      if(pageInfo) {
          pageInfo.textContent = `Showing ${currentResults.length} of ${totalCount} results`;
      }

      // 2. Pass Offset to Render Function
      renderResults(startSerial);

    } catch (err) {
      showBackendError();
      console.error(err);
    }
  }
  /* -------------------------------
     RENDER TABLE
  -------------------------------- */
  function renderResults(startSerial = 1) {
    if(!resultsTable) return;
    resultsTable.innerHTML = "";
    const query = searchInput ? searchInput.value.toLowerCase() : "";

    const filteredResults = currentResults.filter((item) => {
      const searchMatch =
        (item.email && item.email.toLowerCase().includes(query)) ||
        (item.status && item.status.includes(query)) ||
        (item.reason && item.reason.toLowerCase().includes(query));
      return searchMatch;
    });

    if (filteredResults.length === 0) {
      resultsTable.innerHTML = `<tr><td colspan="5" class="p-6 text-center text-slate-500">No results found on this page.</td></tr>`; // Changed colspan to 5
      return;
    }

    filteredResults.forEach((item, index) => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-indigo-50 transition border-b border-slate-100";
      
      const statusHtml = formatStatus(item.status);
      
      let timeStr = "-";
      if (item.verified_at) {
          timeStr = new Date(item.verified_at).toLocaleTimeString();
      }

      // 3. Calculate Row Number
      const rowNumber = startSerial + index;
      
      tr.innerHTML = `
        <td class="p-4 text-slate-400 font-mono text-sm">${rowNumber}</td> <td class="p-4 font-medium text-slate-700">${escapeHTML(item.email)}</td>
        <td class="p-4 font-bold">${statusHtml}</td>
        <td class="p-4 text-slate-600 text-sm max-w-xs truncate" title="${escapeHTML(item.reason || '')}">${escapeHTML(item.reason || '-')}</td>
        <td class="p-4 text-right font-mono text-xs text-slate-400">${escapeHTML(timeStr)}</td>
      `;
      resultsTable.appendChild(tr);
    });
  }

  /* -------------------------------
     HANDLERS
  -------------------------------- */
  if(prevBtn) prevBtn.addEventListener("click", () => loadResultsPage(prevUrl));
  if(nextBtn) nextBtn.addEventListener("click", () => loadResultsPage(nextUrl));

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
      
      // Reload results from page 1 with new filter
      loadResultsPage(`/api/jobs/${jobId}/results/`);
    });
  });

  /* -------------------------------
     HELPERS
  -------------------------------- */
  function showBackendError() {
    if(resultsTable) resultsTable.innerHTML = `<tr><td colspan="5" class="p-6 text-center text-red-600 font-bold">Failed to load results.</td></tr>`;
  }

  function formatStatus(status) {
    if(!status) return "Unknown";
    const s = status.toLowerCase();
    
    let color = "gray";
    if (s === 'valid') color = "green";
    if (s === 'invalid') color = "red";
    if (s === 'disposable') color = "yellow"; // <--- Distinct Color
    if (s === 'risky') color = "orange";
    
    return `<span class="px-2 py-1 rounded-full bg-${color}-100 text-${color}-800 text-xs uppercase tracking-wide font-bold">${status}</span>`;
  }

  function escapeHTML(str) {
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // INITIALIZE
  loadJobStats(); // Load correct summary numbers
  loadResultsPage(`/api/jobs/${jobId}/results/`); // Load first page of table
})();