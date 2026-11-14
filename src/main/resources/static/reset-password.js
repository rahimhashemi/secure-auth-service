"use strict";

const token = new URLSearchParams(location.hash.slice(1)).get("token");
history.replaceState(null, "", location.pathname);

const form = document.getElementById("reset");
const button = document.getElementById("submit");
const result = document.getElementById("result");
const password = document.getElementById("password");
const confirmation = document.getElementById("confirmation");

button.disabled = !token;
if (!token) result.textContent = "Missing reset link. Request a new one.";

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!token) return;
    if (password.value !== confirmation.value) {
        result.textContent = "The passwords must match.";
        return;
    }

    button.disabled = true;
    try {
        const response = await fetch("auth/password-reset/confirm", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "omit",
            cache: "no-store",
            body: JSON.stringify({ token, newPassword: password.value })
        });
        if (response.ok) {
            form.reset();
            form.hidden = true;
            result.textContent = "Password reset. Sign in with your new password.";
            return;
        }
        if (response.status === 429) {
            result.textContent = "Too many attempts. Try again later.";
        } else if (response.status === 400) {
            const error = await response.json();
            result.textContent = error.code === "INVALID_PASSWORD_RESET_TOKEN"
                ? "The reset link is invalid or expired. Request a new link."
                : "Use at least 12 characters and at most 72 UTF-8 bytes.";
        } else {
            result.textContent = "Reset is temporarily unavailable. Try again.";
        }
    } catch {
        result.textContent = "Unable to connect. Try again.";
    }
    button.disabled = false;
});
