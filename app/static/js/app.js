/**
 * PhishGuard AI — Frontend JavaScript
 */

"use strict";

// ── Auto-dismiss alerts after 6 seconds ──────────────────────────
document.querySelectorAll(".alert.alert-dismissible").forEach(el => {
  setTimeout(() => {
    const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
    bsAlert && bsAlert.close();
  }, 6000);
});

// ── Animate stat numbers on page load ────────────────────────────
function animateCounter(el) {
  const target = parseInt(el.textContent.replace(/[^0-9]/g, ""), 10);
  if (isNaN(target) || target === 0) return;
  let current = 0;
  const step = Math.ceil(target / 40);
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    el.textContent = el.textContent.replace(/[0-9]+/, current);
    if (current >= target) clearInterval(timer);
  }, 25);
}

document.querySelectorAll(".pg-stat-value").forEach(el => {
  if (/^\d/.test(el.textContent.trim())) animateCounter(el);
});

// ── Gauge fill animation ──────────────────────────────────────────
const gaugeFill = document.querySelector(".pg-gauge-fill");
if (gaugeFill) {
  const original = gaugeFill.getAttribute("stroke-dasharray");
  gaugeFill.setAttribute("stroke-dasharray", "0 251");
  requestAnimationFrame(() => {
    setTimeout(() => {
      gaugeFill.setAttribute("stroke-dasharray", original);
    }, 100);
  });
}

// ── Tooltip init ──────────────────────────────────────────────────
document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
  new bootstrap.Tooltip(el, { trigger: "hover" });
});
