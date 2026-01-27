/* =========================================================
   ELEMENT REFERENCES
========================================================= */
const fileInput = document.getElementById("fileInput");
const fileInfo = document.getElementById("fileInfo");
const fileName = document.getElementById("fileName");
const fileMeta = document.getElementById("fileMeta");
const removeFile = document.getElementById("removeFile");
const startBtn = document.querySelector(".start-btn");

const uploadTab = document.getElementById("uploadTab");
const pasteTab = document.getElementById("pasteTab");

const uploadSection = document.getElementById("uploadSection");
const pasteSection = document.getElementById("pasteSection");

const emailTextarea = document.getElementById("emailTextarea");
const emailCount = document.getElementById("emailCount");

/* =========================================================
   CLEAN PREVIOUS STATE
========================================================= */
localStorage.removeItem("verificationType");
localStorage.removeItem("emailCount");
localStorage.removeItem("fileName");
localStorage.removeItem("jobId");

/* =========================================================
   JOB ID (SIMULATED BACKEND)
========================================================= */
function generateJobId() {
  return "JOB-" + Math.floor(Math.random() * 9000 + 1000);
}

const jobId = generateJobId();
document.getElementById("jobId").textContent = jobId;

/* =========================================================
   EMAIL VALIDATION
========================================================= */
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/* =========================================================
   START BUTTON STATE CONTROL
========================================================= */
function updateStartButtonState() {
  const isUploadActive = uploadTab.classList.contains("active");
  const isPasteActive = pasteTab.classList.contains("active");

  if (isUploadActive) {
    startBtn.disabled = fileInput.files.length === 0;
    return;
  }

  if (isPasteActive) {
    const validEmails = emailTextarea.value
      .split(/\n|,/)
      .map((e) => e.trim())
      .filter(isValidEmail);

    startBtn.disabled = validEmails.length === 0;
    return;
  }

  startBtn.disabled = true;
}

/* =========================================================
   FILE UPLOAD HANDLING
========================================================= */
fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];
  if (!file) return;

  if (!["text/csv", "text/plain"].includes(file.type)) {
    alert("Only CSV or TXT files are allowed.");
    fileInput.value = "";
    return;
  }

  fileName.textContent = file.name;
  fileMeta.textContent = `${(file.size / 1024 / 1024).toFixed(2)} MB`;
  fileInfo.classList.remove("hidden");

  localStorage.setItem("verificationType", "file");
  localStorage.setItem("fileName", file.name);
  localStorage.setItem("jobId", jobId);

  updateStartButtonState();
});

/* =========================================================
   REMOVE FILE
========================================================= */
removeFile.addEventListener("click", () => {
  fileInput.value = "";
  fileInfo.classList.add("hidden");

  localStorage.removeItem("verificationType");
  localStorage.removeItem("fileName");

  updateStartButtonState();
});

/* =========================================================
   TAB SWITCHING
========================================================= */
uploadTab.addEventListener("click", () => {
  uploadTab.classList.add("active");
  pasteTab.classList.remove("active");

  uploadSection.classList.remove("hidden");
  pasteSection.classList.add("hidden");

  updateStartButtonState();
});

pasteTab.addEventListener("click", () => {
  pasteTab.classList.add("active");
  uploadTab.classList.remove("active");

  pasteSection.classList.remove("hidden");
  uploadSection.classList.add("hidden");

  updateStartButtonState();
});

/* =========================================================
   PASTE EMAIL HANDLING
========================================================= */
emailTextarea.addEventListener("input", () => {
  const rawEmails = emailTextarea.value
    .split(/\n|,/)
    .map((e) => e.trim())
    .filter(Boolean);

  const validEmails = rawEmails.filter(isValidEmail);

  emailCount.textContent = `${validEmails.length} valid email(s) detected`;

  if (validEmails.length > 0) {
    localStorage.setItem("verificationType", "paste");
    localStorage.setItem("emailCount", validEmails.length);
    localStorage.setItem("jobId", jobId);
  } else {
    localStorage.removeItem("verificationType");
    localStorage.removeItem("emailCount");
  }

  updateStartButtonState();
});

/* =========================================================
   START VERIFICATION (DB MODE)
========================================================= */
async function startVerification() {
  const isUploadActive = uploadTab.classList.contains("active");
  const formData = new FormData();

  // 1. Prepare Data
  if (isUploadActive) {
    if (fileInput.files.length === 0) return alert("Please upload a file.");
    formData.append("file", fileInput.files[0]);
  } else {
    const emails = emailTextarea.value.split(/\n|,/).map(e => e.trim()).filter(isValidEmail);
    if (emails.length === 0) return alert("Enter valid emails.");
    emails.forEach(e => formData.append("emails", e));
  }

  // 2. DISABLE TEST MODE (Save to DB)
  // We do NOT append 'test_mode' here. 
  // The serializer defaults test_mode to False, which triggers the DB save logic.

  // 3. UI Feedback
  startBtn.textContent = "Processing...";
  startBtn.disabled = true;

  try {
    // 4. Call DRF Endpoint
    const response = await fetch("/api/jobs/", {
      method: "POST",
      body: formData,
      headers: {
        // CSRF Token is required for POST requests in Django
        'X-CSRFToken': getCookie('csrftoken') 
      }
    });

    if (!response.ok) {
        const errData = await response.json();
        throw new Error(JSON.stringify(errData));
    }

    const data = await response.json();
    
    // 5. Store ID and Redirect
    localStorage.setItem("jobId", data.job_id);
    window.location.href = "/verification-progress/"; 

  } catch (error) {
    console.error(error);
    alert("Error starting job: " + error.message);
    startBtn.textContent = "Start Verification";
    startBtn.disabled = false;
  }
}

// Helper to get CSRF token from cookies
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Bind Click (Runs in DB Mode now)
startBtn.addEventListener("click", () => startVerification());

/* =========================================================
   INITIAL STATE
========================================================= */
updateStartButtonState();
