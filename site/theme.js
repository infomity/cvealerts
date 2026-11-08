// Infomity Obsidian Theme Controller
// Defaults to dark obsidian luxury theme unless explicitly toggled to light.
// Preserves choices in localStorage and syncs meta theme-color and UI icons.
(function () {
  const KEY_THEME = "theme";
  const KEY_LEGACY = "cvea-theme";
  const root = document.documentElement;

  function saved() {
    try {
      const v = localStorage.getItem(KEY_THEME) || localStorage.getItem(KEY_LEGACY);
      return v === "light" || v === "dark" ? v : null;
    } catch (e) {
      return null;
    }
  }

  function apply(theme) {
    if (theme === "light") {
      root.setAttribute("data-theme", "light");
    } else {
      root.removeAttribute("data-theme");
    }

    const isLight = theme === "light";
    const color = isLight ? "#f8fafc" : "#07090e";
    const metas = document.querySelectorAll('meta[name="theme-color"]');
    metas.forEach(function (m) { m.setAttribute("content", color); });

    const icon = document.getElementById("themeIcon");
    if (icon) {
      icon.textContent = isLight ? "☀️" : "🌙";
    }

    const btn = document.getElementById("themeBtn");
    if (btn) {
      const label = isLight ? "Switch to dark theme" : "Switch to light theme";
      btn.setAttribute("aria-label", label);
      btn.setAttribute("title", label);
    }
  }

  // Initial apply: default to obsidian dark unless user previously picked light
  const initial = saved() === "light" ? "light" : "dark";
  apply(initial);

  document.addEventListener("DOMContentLoaded", function () {
    apply(saved() === "light" ? "light" : "dark");
    const btn = document.getElementById("themeBtn");
    if (btn) {
      btn.addEventListener("click", function () {
        const isCurrentLight = root.getAttribute("data-theme") === "light";
        const next = isCurrentLight ? "dark" : "light";
        try {
          localStorage.setItem(KEY_THEME, next);
          localStorage.setItem(KEY_LEGACY, next);
        } catch (e) {}
        apply(next);
      });
    }
  });
})();

// Mobile navigation menu toggle helper
window.toggleMobileMenu = function () {
  const container = document.querySelector(".navbar-container");
  const btn = document.getElementById("mobileMenuBtn");
  if (!container) return;
  const isOpen = container.classList.toggle("is-open");
  if (btn) btn.setAttribute("aria-expanded", isOpen ? "true" : "false");
};

// Auto-close menu when clicking outside or clicking any nav link
document.addEventListener("click", function (e) {
  const container = document.querySelector(".navbar-container");
  if (!container || !container.classList.contains("is-open")) return;
  if (!container.contains(e.target)) {
    container.classList.remove("is-open");
    const btn = document.getElementById("mobileMenuBtn");
    if (btn) btn.setAttribute("aria-expanded", "false");
  }
});

document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".navbar-links .nav-link").forEach(function (link) {
    link.addEventListener("click", function () {
      const container = document.querySelector(".navbar-container");
      if (container && container.classList.contains("is-open")) {
        container.classList.remove("is-open");
        const btn = document.getElementById("mobileMenuBtn");
        if (btn) btn.setAttribute("aria-expanded", "false");
      }
    });
  });
});
