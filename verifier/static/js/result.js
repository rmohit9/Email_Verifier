
(() => {
  /* -------------------------------
     SAFETY CHECK
  -------------------------------- */
  const jobId = localStorage.getItem("jobId");

  if (!jobId) {
    alert("No verification job found. Redirecting to upload page.");
    window.location.href = "upload.html";
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

  /* -------------------------------
     STATE
  -------------------------------- */
  let allResults = [];
  let activeFilter = "all";

  /* -------------------------------
     INITIAL META
  -------------------------------- */
  jobIdEl.textContent = jobId;
  processedAtEl.textContent = new Date().toLocaleString();

  /* -------------------------------
     LOAD REAL RESULTS FROM BACKEND
  -------------------------------- */
  async function loadResults() {
    try {
      const res = await fetch(`/api/results/${jobId}`);

      if (!res.ok) {
        throw new Error("Backend not responding");
      }

      const data = await res.json();

      /*
        Expected backend response:
        {
          results: [
            {
              email: "test@example.com",
              status: "Valid",
              reason: "SMTP Connect Success",
              timestamp: "14:01:23"
            }
          ]
        }
      */

      if (!data.results || !Array.isArray(data.results)) {
        throw new Error("Invalid backend response");
      }

      allResults = data.results;
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
    resultsTable.innerHTML = "";

    const query = searchInput.value.toLowerCase();

    const filteredResults = allResults.filter((item) => {
      const status = item.status.toLowerCase();

      const statusMatch = activeFilter === "all" || status === activeFilter;

      const searchMatch =
        item.email.toLowerCase().includes(query) ||
        item.status.toLowerCase().includes(query) ||
        item.reason.toLowerCase().includes(query);

      return statusMatch && searchMatch;
    });

    if (filteredResults.length === 0) {
      resultsTable.innerHTML = `
        <tr>
          <td colspan="4" class="p-6 text-center text-slate-500">
            No results found.
          </td>
        </tr>
      `;
      return;
    }

    filteredResults.forEach((item) => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-indigo-50 transition";

      tr.innerHTML = `
        <td class="p-4 font-medium">${escapeHTML(item.email)}</td>
        <td class="p-4 font-bold">${formatStatus(item.status)}</td>
        <td class="p-4 text-slate-600">${escapeHTML(item.reason)}</td>
        <td class="p-4 text-right font-mono text-slate-500">
          ${escapeHTML(item.timestamp)}
        </td>
      `;

      resultsTable.appendChild(tr);
    });
  }

  /* -------------------------------
     FILTER BUTTONS
  -------------------------------- */
  filterButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      filterButtons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");

      activeFilter = btn.dataset.status.toLowerCase();
      renderResults();
    });
  });

  /* -------------------------------
     SEARCH
  -------------------------------- */
  searchInput.addEventListener("input", renderResults);

  /* -------------------------------
     EXPORT CSV (REAL DOWNLOAD)
  -------------------------------- */
  exportBtn.addEventListener("click", () => {
    window.location.href = `/api/export/${jobId}`;
  });

  /* -------------------------------
     NEW VERIFICATION
  -------------------------------- */
  newBtn.addEventListener("click", () => {
    localStorage.removeItem("jobId");
    window.location.href = "upload.html";
  });

  /* -------------------------------
     HELPERS
  -------------------------------- */
  function showBackendError() {
    resultsTable.innerHTML = `
      <tr>
        <td colspan="4" class="p-6 text-center text-red-600 font-bold">
          Backend is not responding. Please try again later.
        </td>
      </tr>
    `;
  }

  function formatStatus(status) {
    const map = {
      Valid: "text-green-600",
      Invalid: "text-red-600",
      Disposable: "text-orange-500",
      "Catch-all": "text-purple-600",
      Unknown: "text-gray-500",
    };

    const cls = map[status] || "text-slate-600";
    return `<span class="${cls}">${status}</span>`;
  }

  function escapeHTML(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  /* -------------------------------
     INIT
  -------------------------------- */
  loadResults();
})();
