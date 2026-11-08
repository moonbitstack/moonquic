// The hero: one real Initial packet, drawn as the punched card a QUIC packet is — a fixed set of
// fields in a fixed order, each bit either punched or not. The bytes come from the library itself,
// compiled to JavaScript for this page; when that build is absent (a local checkout that has not
// run the docs build) the card is drawn from a fixed pattern and says so.
(function () {
  var canvas = document.getElementById("card");
  if (!canvas) {
    return;
  }
  var caption = document.getElementById("card-caption");
  var COLUMNS = 16;
  var ROWS = 12;

  function ink(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function draw(bytes, real) {
    var ratio = Math.min(window.devicePixelRatio || 1, 2);
    var box = canvas.getBoundingClientRect();
    var width = Math.max(1, Math.round(box.width));
    var height = Math.max(1, Math.round(width * 0.78));
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    var ctx = canvas.getContext("2d");
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, width, height);

    var paper = ink("--card");
    var hole = ink("--hole");
    var rule = ink("--rule-2");

    ctx.fillStyle = paper;
    ctx.fillRect(0, 0, width, height);
    ctx.strokeStyle = rule;
    ctx.lineWidth = 1;
    ctx.strokeRect(0.5, 0.5, width - 1, height - 1);

    var pad = Math.max(10, width * 0.022);
    var gridW = width - pad * 2;
    var gridH = height - pad * 2;
    var cell = Math.min(gridW / COLUMNS, gridH / ROWS);
    var originX = (width - cell * COLUMNS) / 2;
    var originY = pad;

    ctx.fillStyle = hole;
    for (var i = 0; i < COLUMNS * ROWS; i++) {
      var value = bytes[i % bytes.length];
      var cx = originX + (i % COLUMNS) * cell;
      var cy = originY + Math.floor(i / COLUMNS) * cell;
      var holeSize = cell * 0.3;
      for (var bit = 0; bit < 8; bit++) {
        if ((value >> (7 - bit)) & 1) {
          var bx = cx + cell * 0.14 + (bit % 2) * holeSize * 1.12;
          var by = cy + cell * 0.14 + Math.floor(bit / 2) * holeSize * 1.12;
          ctx.fillRect(bx, by, holeSize, holeSize);
        }
      }
    }

    if (caption) {
      caption.textContent = real
        ? "Initial packet, " + bytes.length + " bytes, first " + COLUMNS * ROWS + " punched"
        : "Initial packet, drawn from a fixed pattern";
    }
  }

  function pattern() {
    var bytes = new Uint8Array(COLUMNS * ROWS);
    var seed = 0x9e3779b9;
    for (var i = 0; i < bytes.length; i++) {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      bytes[i] = seed >>> 24;
    }
    return bytes;
  }

  function paint() {
    draw(pattern(), false);
    import("../engine/moonquic.js")
      .then(function (engine) {
        var packet = JSON.parse(engine.initial());
        var bytes = packet.hex.match(/.{2}/g).map(function (pair) {
          return parseInt(pair, 16);
        });
        draw(Uint8Array.from(bytes), true);
      })
      .catch(function () {
        // No build here: the pattern stands, and the caption says as much.
      });
  }

  var timer = null;
  window.addEventListener("resize", function () {
    clearTimeout(timer);
    timer = setTimeout(paint, 120);
  });
  document.addEventListener("click", function (event) {
    if (event.target.closest("[data-theme-toggle]")) {
      setTimeout(paint, 0);
    }
  });
  paint();
})();
