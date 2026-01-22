/* =========================================================
   CONFIG
========================================================= */
const BACKEND_TIMEOUT = 4000; // ms (4 seconds)
let backendResponded = false;

/* =========================================================
   ELEMENT REFERENCES
========================================================= */
const jobIdEl = document.getElementById("jobId");
const progressPercentEl = document.getElementById("progressPercent");
const progressBar = document.getElementById("progressBar");
const currentStepEl = document.getElementById("currentStep");
const timeRemainingEl = document.getElementById("timeRemaining");

const processedEl = document.getElementById("processedEmails");
const totalEl = document.getElementById("totalEmails");
const validEl = document.getElementById("validEmails");
const invalidEl = document.getElementById("invalidEmails");
const riskyEl = document.getElementById("riskyEmails");

const logBody = document.getElementById("logBody");

/* =========================================================
   INITIAL SAFE UI STATE 
========================================================= */
jobIdEl.textContent = localStorage.getItem("jobId") || "N/A";

progressPercentEl.textContent = "—";
progressBar.style.width = "0%";
currentStepEl.textContent = "Waiting for backend...";
timeRemainingEl.textContent = "--";

processedEl.textContent = "--";
totalEl.textContent = "--";
validEl.textContent = "--";
invalidEl.textContent = "--";
riskyEl.textContent = "--";

/* =========================================================
   PIPELINE STATE CONTROLLER
========================================================= */
function setPipelineState(stepName, state) {
  const step = document.querySelector(`[data-step="${stepName}"]`);
  if (!step) return;

  const icon = step.querySelector(".pipeline-icon");
  const status = step.querySelector(".status");

  icon.className = "pipeline-icon";
  status.className = "status";

  if (state === "completed") {
    icon.classList.add("pipeline-completed");
    icon.innerHTML = `<span class="material-symbols-outlined">check</span>`;
    status.classList.add("success");
    status.textContent = "Completed";
  }

  if (state === "running") {
    icon.classList.add("pipeline-running");
    icon.innerHTML = `<span class="material-symbols-outlined">sync</span>`;
    status.classList.add("running");
    status.textContent = "Running";
  }

  if (state === "pending") {
    icon.classList.add("pipeline-pending");
    icon.innerHTML = `<span class="material-symbols-outlined">pending</span>`;
    status.classList.add("pending");
    status.textContent = "Pending";
  }

  if (state === "error") {
    icon.classList.add("pipeline-error");
    icon.innerHTML = `<span class="material-symbols-outlined">error</span>`;
    status.classList.add("error");
    status.textContent = "Error";
  }
}

/* =========================================================
   BACKEND ERROR STATE (SAFE FAIL)
========================================================= */
function showBackendError() {
  currentStepEl.textContent = "Backend is not responding";
  progressPercentEl.textContent = "—";
  progressBar.style.width = "0%";
  timeRemainingEl.textContent = "--";

  processedEl.textContent = "--";
  totalEl.textContent = "--";
  validEl.textContent = "--";
  invalidEl.textContent = "--";
  riskyEl.textContent = "--";

  setPipelineState("Syntax Validation", "completed");
  setPipelineState("Domain Check", "completed");
  setPipelineState("MX Record Lookup", "error");
  setPipelineState("SMTP Handshake", "pending");
  setPipelineState("Disposable Detection", "pending");

  const errorLog = document.createElement("p");
  errorLog.style.color = "#f87171";
  errorLog.textContent = `[${new Date().toLocaleTimeString()}] ERROR: Backend is not responding`;
  logBody.prepend(errorLog);
}

/* =========================================================
   BACKEND FETCH PLACEHOLDER
    Replace this with real API / WebSocket
========================================================= */
function fetchBackendProgress() {
  //  Simulate backend down
  return null;

  /*
  //  Example real backend response (future)
  return {
    total: 2500,
    processed: 1200,
    valid: 1100,
    invalid: 60,
    risky: 40,
    progress: 48,
    step: "MX Record Lookup"
  };
  */
}

/* =========================================================
   HANDLE BACKEND DATA (WHEN AVAILABLE)
========================================================= */
function handleBackendData(data) {
  backendResponded = true;

  totalEl.textContent = data.total;
  processedEl.textContent = data.processed;
  validEl.textContent = data.valid;
  invalidEl.textContent = data.invalid;
  riskyEl.textContent = data.risky;

  progressPercentEl.textContent = data.progress + "%";
  progressBar.style.width = data.progress + "%";
  currentStepEl.textContent = data.step;
  timeRemainingEl.textContent = "calculating...";

  setPipelineState("Syntax Validation", "completed");
  setPipelineState("Domain Check", "completed");
  setPipelineState("MX Record Lookup", "running");
  setPipelineState("SMTP Handshake", "pending");
  setPipelineState("Disposable Detection", "pending");

  const log = document.createElement("p");
  log.textContent = `[${new Date().toLocaleTimeString()}] Backend progress updated`;
  logBody.prepend(log);
}

/* =========================================================
   BACKEND TIMEOUT GUARD
========================================================= */
setTimeout(() => {
  if (!backendResponded) {
    showBackendError();
  }
}, BACKEND_TIMEOUT);

/* =========================================================
   POLLING LOOP (SAFE)
========================================================= */
const pollInterval = setInterval(() => {
  const backendData = fetchBackendProgress();

  if (backendData) {
    handleBackendData(backendData);
  }
}, 1000);

async function pollJobStatus() {
  const jobId = localStorage.getItem("jobId");
  if (!jobId) return;

  try {
    const res = await fetch(`/api/job-status/${jobId}`);
    if (!res.ok) throw new Error("Backend not responding");

    const data = await res.json();

    updateProgressUI(data);

    if (data.progress === 100) {
      setTimeout(() => {
        window.location.href = "verification-results.html";
      }, 800);
    }
  } catch (err) {
    showBackendError();
  }
}

setInterval(pollJobStatus, 3000);
