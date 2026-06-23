// Mobile nav drawer behaviour, extracted from an inline onclick on .sidebar so
// the panel can ship a strict `script-src 'self'` CSP (an inline event-handler
// attribute would require 'unsafe-inline', which defeats the XSS protection).
// Loaded via <script src> after the markup, so .sidebar already exists; the
// sidebar is static (app.js only re-renders #view), so this listener persists.
(function () {
  "use strict";
  var sidebar = document.querySelector(".sidebar");
  if (!sidebar) return;
  // Tapping any nav item closes the off-canvas drawer (uncheck the CSS toggle).
  sidebar.addEventListener("click", function (event) {
    if (event.target.closest(".nav-item")) {
      var toggle = document.getElementById("navtoggle");
      if (toggle) toggle.checked = false;
    }
  });
})();
