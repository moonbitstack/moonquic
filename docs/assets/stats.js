// The few numbers on the pages that would otherwise drift: read from a file the generator writes,
// so a version bump is one edit in moon.mod and one run of scripts/gen_api.py.
(function () {
  fetch("assets/stats.json")
    .then(function (response) {
      return response.ok ? response.json() : null;
    })
    .then(function (stats) {
      if (!stats) {
        return;
      }
      for (const node of document.querySelectorAll("[data-stat]")) {
        const key = node.getAttribute("data-stat");
        if (stats[key] !== undefined) {
          node.textContent = String(stats[key]);
        }
      }
    })
    .catch(function () {
      // A page opened from disk without the JSON keeps its placeholders.
    });
})();
