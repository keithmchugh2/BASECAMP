const CALENDLY_URL = "https://calendly.com/basecampconsultants/basecamp-discovery-session";

const form = document.getElementById("discoveryForm");
const formNote = document.getElementById("formNote");
const yearEl = document.getElementById("year");
const calendlyLink = document.getElementById("calendlyLink");

if (yearEl) {
  yearEl.textContent = new Date().getFullYear();
}

if (calendlyLink) {
  calendlyLink.href = CALENDLY_URL;
}

if (form) {
  form.addEventListener("submit", (event) => {
    event.preventDefault();

    const data = new FormData(form);
    const fullName = (data.get("fullName") || "").toString().trim();
    const email = (data.get("email") || "").toString().trim();
    const phone = (data.get("phone") || "").toString().trim();
    const goal = (data.get("goal") || "").toString().trim();
    const timeWindow = (data.get("timeWindow") || "").toString().trim();

    if (!fullName || !email || !goal || !timeWindow) {
      formNote.textContent = "Please complete all required fields.";
      formNote.style.color = "#9f3a21";
      return;
    }

    const submitButton = form.querySelector("button[type='submit']");
    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = "Sending...";
    }
    formNote.textContent = "";

    fetch("/api/discovery", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fullName, email, phone, goal, timeWindow }),
    })
      .then((response) => response.json().then((body) => ({ ok: response.ok, body })))
      .then(({ ok, body }) => {
        if (!ok || !body.ok) {
          throw new Error(body.error || "Unable to send request.");
        }
        formNote.textContent = "Thanks. Your discovery request has been submitted.";
        formNote.style.color = "#175047";
        form.reset();
      })
      .catch((error) => {
        formNote.textContent = error.message || "Unable to submit request right now.";
        formNote.style.color = "#9f3a21";
      })
      .finally(() => {
        if (submitButton) {
          submitButton.disabled = false;
          submitButton.textContent = "Send Discovery Request";
        }
      });
  });
}
