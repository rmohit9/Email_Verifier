/************************************
 * DASHBOARD STATS
 * Backend team:
 * Create API: GET /api/admin/dashboard
 *
 * Expected response:
 * {
 *   totalJobs: Number,          // 44291
 *   jobsGrowth: Number,         // 12
 *   emailsVerified: Number,     // 1240000
 *   emailsGrowth: Number,       // 5.2
 *   systemLoad: Number          // 84
 * }
 ************************************/
async function loadDashboardStats() {
  try {
    const res = await fetch("/api/admin/dashboard", {
      credentials: "include", // session / JWT auth
    });

    const data = await res.json();

    /* -------- Total Jobs -------- */
    document.getElementById("totalJobs").textContent =
      data.totalJobs.toLocaleString();

    const jobsGrowthEl = document.getElementById("jobsGrowth");
    if (jobsGrowthEl) {
      jobsGrowthEl.textContent = data.jobsGrowth;
    }

    /* -------- Emails Verified -------- */
    document.getElementById("emailsVerified").textContent =
      data.emailsVerified >= 1000000
        ? (data.emailsVerified / 1000000).toFixed(2) + "M"
        : data.emailsVerified.toLocaleString();

    const emailsGrowthEl = document.getElementById("emailsGrowth");
    if (emailsGrowthEl) {
      emailsGrowthEl.textContent = data.emailsGrowth;
    }

    /* -------- System Load -------- */
    const systemLoadEl = document.getElementById("systemLoad");
    const systemLoadBigEl = document.getElementById("systemLoadBig");

    if (systemLoadEl) systemLoadEl.textContent = data.systemLoad;
    if (systemLoadBigEl) systemLoadBigEl.textContent = data.systemLoad;
  } catch (err) {
    console.error("Failed to load dashboard stats", err);
  }
}

/************************************
 * RECENT BATCH JOBS
 * Backend team:
 * Create API: GET /api/admin/jobs?limit=5
 *
 * Response format:
 * [
 *   {
 *     jobId: "JO-4492",
 *     adminName: "Admin Name",
 *     status: "Verified | Processing | Failed",
 *     totalRecords: 12500,
 *     createdAt: "2025-10-24T05:12:00Z"
 *   }
 * ]
 ************************************/
async function loadRecentJobs() {
  try {
    const res = await fetch("/api/admin/jobs?limit=5", {
      credentials: "include",
    });

    const jobs = await res.json();
    const jobsTable = document.getElementById("jobsTable");

    jobsTable.innerHTML = "";

    jobs.forEach((job) => {
      jobsTable.innerHTML += `
        <tr>
          <td>${job.jobId}</td>
          <td>${job.adminName}</td>
          <td>${job.status}</td>
          <td>${job.totalRecords.toLocaleString()}</td>
          <td>${new Date(job.createdAt).toLocaleString()}</td>
        </tr>
      `;
    });
  } catch (err) {
    console.error("Failed to load recent jobs", err);
  }
}

/************************************
 * REAL-TIME UPDATES
 * Backend team:
 * - Polling every 15 seconds
 * - Can be replaced with WebSockets / SSE later
 ************************************/
setInterval(loadRecentJobs, 15000);

/************************************
 * VIEW ALL JOBS
 * Backend team:
 * Page should load all jobs using:
 * GET /api/admin/jobs
 ************************************/
function viewAllJobs() {
  window.location.href = "/admin/jobs.html";
}

/************************************
 * INITIAL LOAD
 ************************************/
loadDashboardStats();
loadRecentJobs();
