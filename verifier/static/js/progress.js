/* =========================================================
   ELEMENT REFERENCES
========================================================= */
const jobIdEl = document.getElementById("jobId");
const progressPercentEl = document.getElementById("progressPercent");
const progressBar = document.getElementById("progressBar");
const currentStepEl = document.getElementById("currentStep");
const timeRemainingEl = document.getElementById("timeRemaining");

// Ensure these IDs match your HTML exactly
const processedEl = document.getElementById("processedEmails");
const totalEl = document.getElementById("totalEmails");
const validEl = document.getElementById("validEmails");
const invalidEl = document.getElementById("invalidEmails");
const riskyEl = document.getElementById("riskyEmails");

const logBody = document.getElementById("logBody");
const viewResultsBtn = document.getElementById("viewResultsBtn");

/* =========================================================
   STATE
========================================================= */
const jobId = localStorage.getItem("jobId");
let isComplete = false;

/* =========================================================
   INIT CHECK
========================================================= */
if (!jobId) {
  alert("No active job found. Redirecting to upload.");
  window.location.href = "/upload/";
} else {
  if (jobIdEl) jobIdEl.textContent = jobId;
}

/* =========================================================
   POLLING FUNCTION (DRF / REDIS)
========================================================= */
async function checkProgress() {
  if (isComplete) return;

  try {
    // Call the new DRF endpoint
    const res = await fetch(`/api/jobs/${jobId}/`);

    if (!res.ok) {
      if (res.status === 404) {
        if (currentStepEl) currentStepEl.textContent = "Job not found (Expired?)";
        return;
      }
      throw new Error("API Error");
    }

    const data = await res.json();
    updateUI(data);

    if (data.status === "completed" || data.status === "failed") {
      isComplete = true;
      finalize(data);
    } else {
      // Poll again in 1 second
      setTimeout(checkProgress, 1000);
    }
  } catch (err) {
    console.error("Polling error:", err);
    if (currentStepEl) currentStepEl.textContent = "Connection Error...";
    setTimeout(checkProgress, 3000); // Retry slower
  }
}

/* =========================================================
   UI UPDATES
========================================================= */
function updateUI(data) {
  // Update Counts
  const processed = data.processed_count || 0;
  const total = data.total_count || 0;
  const percentage = data.progress_percentage || 0;

  if (processedEl) processedEl.textContent = processed;
  if (totalEl) totalEl.textContent = total;

  // Note: Test Mode might not send live valid/invalid counts until the end
  if (validEl) validEl.textContent = data.valid_count !== undefined ? data.valid_count : "--";
  if (invalidEl) invalidEl.textContent = data.invalid_count !== undefined ? data.invalid_count : "--";

  // Update Status Text
  if (progressBar) progressBar.style.width = `${percentage}%`;
  if (progressPercentEl) progressPercentEl.textContent = `${Math.round(percentage)}%`;

  // --- NEW PIPELINE VISUAL LOGIC ---

  // 1. Syntax & Disposable are practically instant (0-5%)
  if (percentage >= 0) {
    markStepCompleted("Syntax Validation");
    markStepCompleted("Disposable Detection");
  }

  // 2. Domain & MX happen next (5-15%)
  if (percentage > 5) {
    markStepCompleted("Domain Check");
    markStepRunning("MX Record Lookup");
  }

  // 3. MX is done, SMTP starts (15%+)
  if (percentage > 15) {
    markStepCompleted("MX Record Lookup");
    markStepRunning("SMTP Handshake");
  }

  // 4. Finished
  if (percentage >= 100) {
    markStepCompleted("SMTP Handshake");
  }
}

function finalize(data) {
  if (data.status === "completed") {
    // Show results button if it exists
    if (viewResultsBtn) {
      viewResultsBtn.disabled = false;
      viewResultsBtn.classList.remove("opacity-50", "cursor-not-allowed");
    }

    // Auto-redirect to results after short delay
    setTimeout(() => {
      window.location.href = "/verification-results/";
    }, 1000);
  } else {
    alert("Job Failed: " + (data.error_message || "Unknown error"));
  }
}

// Start polling
checkProgress();

function markStepCompleted(stepName) {
  const el = document.querySelector(`[data-step="${stepName}"] .status`);
  if (el) {
    el.textContent = "Completed";
    el.className = "status success";
    el.previousElementSibling.previousElementSibling.className = "pipeline-icon pipeline-completed";
  }
}

function markStepRunning(stepName) {
  const el = document.querySelector(`[data-step="${stepName}"] .status`);
  if (el) {
    el.textContent = "Running";
    el.className = "status running";
    el.previousElementSibling.previousElementSibling.className = "pipeline-icon pipeline-running";
  }
}