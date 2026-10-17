"use strict";

(() => {
  const storageKey = "whitebox-theme";
  const preference = window.matchMedia("(prefers-color-scheme: light)");
  let saved = null;
  try {
    const value = localStorage.getItem(storageKey);
    if (value === "light" || value === "dark") saved = value;
  } catch { /* Theme selection still works when storage is unavailable. */ }

  function apply(theme) {
    const active = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = active;
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = active === "light" ? "#f4f7fb" : "#0b1120";
    document.querySelectorAll(".theme-toggle").forEach((button) => {
      const next = active === "light" ? "dark" : "light";
      button.textContent = next === "light" ? "☀ Chế độ sáng" : "☾ Chế độ tối";
      button.setAttribute("aria-label", `Chuyển sang chế độ ${next === "light" ? "sáng" : "tối"}`);
    });
  }

  apply(saved || (preference.matches ? "light" : "dark"));

  document.addEventListener("DOMContentLoaded", () => {
    apply(saved || (preference.matches ? "light" : "dark"));
    document.querySelectorAll(".theme-toggle").forEach((button) => {
      button.addEventListener("click", () => {
        saved = document.documentElement.dataset.theme === "light" ? "dark" : "light";
        try { localStorage.setItem(storageKey, saved); } catch { /* Keep this tab's selection. */ }
        apply(saved);
      });
    });
  });

  const followSystem = () => { if (!saved) apply(preference.matches ? "light" : "dark"); };
  if (preference.addEventListener) preference.addEventListener("change", followSystem);
  else preference.addListener(followSystem);
})();
