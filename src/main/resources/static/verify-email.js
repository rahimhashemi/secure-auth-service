"use strict";
const token = new URLSearchParams(location.hash.slice(1)).get("token");
history.replaceState(null, "", location.pathname);
const button = document.getElementById("confirm");
const result = document.getElementById("result");
if (!token) { button.disabled = true; result.textContent = "Missing verification token. Request another email."; }
button.addEventListener("click", async () => {
    button.disabled = true;
    try {
        const response = await fetch("/auth/email-verification/confirm", {
            method: "POST", headers: { "Content-Type": "application/json" },
            credentials: "omit", cache: "no-store", body: JSON.stringify({ token })
        });
        result.textContent = response.ok ? "Email verified. You can now sign in."
            : response.status === 429 ? "Too many attempts. Try again later."
            : "The link is invalid or expired. Request another email.";
    } catch { result.textContent = "Unable to connect. Try again."; button.disabled = false; }
});
