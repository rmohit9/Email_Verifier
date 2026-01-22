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
   START VERIFICATION 
========================================================= */
startBtn.addEventListener("click", () => {
  const isUploadActive = uploadTab.classList.contains("active");
  const isPasteActive = pasteTab.classList.contains("active");

  if (isUploadActive && fileInput.files.length === 0) {
    alert("Please upload a CSV or TXT file.");
    return;
  }

  if (isPasteActive) {
    const validEmails = emailTextarea.value
      .split(/\n|,/)
      .map((e) => e.trim())
      .filter(isValidEmail);

    if (validEmails.length === 0) {
      alert("Please enter at least one valid email address.");
      return;
    }
  }


  window.location.href = "../Progress page/verification-progress.html";
});

/* =========================================================
   INITIAL STATE
========================================================= */
updateStartButtonState();
