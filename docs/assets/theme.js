// The theme control. The choice lives for the visit — navigation between pages keeps it, a reload
// drops it and the page follows the system again — so a stray click never sticks to a reader who
// came to look at the site once.
(function () {
  var KEY = "moonquic-theme";
  var root = document.documentElement;
  var media = window.matchMedia("(prefers-color-scheme: dark)");

  function stored() {
    try {
      return window.sessionStorage.getItem(KEY);
    } catch (e) {
      return null;
    }
  }

  function remember(value) {
    try {
      window.sessionStorage.setItem(KEY, value);
    } catch (e) {
      // A reader with storage turned off still gets the toggle; it just does not survive a link.
    }
  }

  function paint(value) {
    root.dataset.theme = value;
    var button = document.querySelector("[data-theme-toggle]");
    if (button) {
      button.setAttribute("aria-label", value === "dark" ? "Switch to the light page" : "Switch to the dark page");
      button.setAttribute("aria-pressed", value === "dark" ? "true" : "false");
    }
  }

  paint(root.dataset.theme === "dark" ? "dark" : "light");

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-theme-toggle]");
    if (!button) {
      return;
    }
    var next = root.dataset.theme === "dark" ? "light" : "dark";
    remember(next);
    paint(next);
  });

  // While the reader has said nothing of their own, the page follows the system as it changes.
  media.addEventListener("change", function (event) {
    if (!stored()) {
      paint(event.matches ? "dark" : "light");
    }
  });

  // The page-level scrollbar keeps its room and loses its thumb at the top, so the measure of the
  // page is the same before and after the first scroll.
  var mark = function () {
    root.classList.toggle("at-top", window.scrollY === 0);
  };
  window.addEventListener("scroll", mark, { passive: true });
  mark();
})();
