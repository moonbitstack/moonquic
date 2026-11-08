// The capture page: three readings of the same bytes, each printed by the library compiled to
// JavaScript. The page owns layout and highlight; the library owns every byte and every range.
import { initial, params } from "../engine/moonquic.js";

const packet = JSON.parse(initial());
const declared = JSON.parse(params());

const hexBox = document.getElementById("hex");
const fieldsBox = document.getElementById("fields");
const note = document.getElementById("note");
const meterBytes = document.getElementById("m-bytes");
const meterFields = document.getElementById("m-fields");
const meterWhat = document.getElementById("m-what");

const stages = {
  header: {
    hex: packet.hex,
    pad: { from: 27, to: packet.length - 16 },
    tag: { from: packet.length - 16, to: packet.length },
    items: packet.fields.map((f) => ({
      name: f.name,
      from: f.from,
      to: f.to,
      value: f.value,
      note: f.note,
    })),
    what: "the header, as anything on the path sees it",
  },
  frames: {
    hex: packet.hex,
    pad: { from: 27, to: packet.length - 16 },
    tag: { from: packet.length - 16, to: packet.length },
    items: packet.frames.map((f) => ({
      name: f.type,
      from: f.from,
      to: f.to,
      value: f.to - f.from + " bytes",
      note: f.note,
    })),
    what: "what the peer reads once the packet opens",
  },
  params: {
    hex: declared.hex,
    tag: null,
    items: declared.params.map((p) => ({
      name: p.name,
      from: p.from,
      to: p.to,
      value: p.value,
      note: "0x" + p.code.toString(16) + " · " + p.note,
    })),
    what: "the block a handshake carries beside the packet",
  },
};

let stage = "header";
let selected = -1;
let spans = [];

function bytesOf(hex) {
  return hex.match(/.{2}/g) || [];
}

function paintHex() {
  const view = stages[stage];
  const bytes = bytesOf(view.hex);
  spans = [];
  const rows = [];
  for (let at = 0; at < bytes.length; at += 16) {
    const row = document.createElement("div");
    row.className = "row";
    const off = document.createElement("span");
    off.className = "off";
    off.textContent = at.toString().padStart(4, "0");
    const line = document.createElement("span");
    for (let i = 0; i < 16 && at + i < bytes.length; i++) {
      const index = at + i;
      const span = document.createElement("span");
      span.className = "byte" + (index % 2 ? "" : " even");
      span.textContent = bytes[index];
      span.dataset.at = String(index);
      if (view.tag && index >= view.tag.from && index < view.tag.to) {
        span.classList.add("is-tag");
      }
      if (view.pad && index >= view.pad.from && index < view.pad.to) {
        span.style.opacity = "0.45";
      }
      line.appendChild(span);
      spans.push(span);
      line.appendChild(document.createTextNode(" "));
    }
    row.append(off, line);
    rows.push(row);
  }
  hexBox.replaceChildren(...rows);
}

function paintFields() {
  const view = stages[stage];
  const rows = view.items.map((item, index) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "fieldrow";
    row.dataset.index = String(index);

    const name = document.createElement("span");
    name.className = "fieldrow__name";
    name.textContent = item.name;

    const range = document.createElement("span");
    range.className = "fieldrow__range";
    range.textContent = item.from + "–" + (item.to - 1) + " · " + (item.to - item.from) + "B";

    const value = document.createElement("span");
    value.className = "fieldrow__value";
    value.textContent = item.value;

    const why = document.createElement("span");
    why.className = "fieldrow__note";
    why.textContent = item.note;

    row.append(name, range, value, why);
    return row;
  });
  fieldsBox.replaceChildren(...rows);
}

function clearHighlight() {
  for (const span of spans) {
    span.classList.remove("is-field", "is-on");
  }
  for (const row of fieldsBox.children) {
    row.classList.remove("is-on");
  }
}

function highlight(index) {
  clearHighlight();
  if (index < 0 || index >= stages[stage].items.length) {
    return;
  }
  const item = stages[stage].items[index];
  for (let at = item.from; at < item.to && at < spans.length; at++) {
    spans[at].classList.add("is-field");
  }
  const first = spans[item.from];
  if (first) {
    first.classList.add("is-on");
    const box = hexBox.getBoundingClientRect();
    const spot = first.getBoundingClientRect();
    if (spot.top < box.top || spot.bottom > box.bottom) {
      first.scrollIntoView({ block: "nearest" });
    }
  }
  const row = fieldsBox.children[index];
  if (row) {
    row.classList.add("is-on");
  }
  note.textContent = item.name + " — " + item.note;
}

function fieldAt(byte) {
  const view = stages[stage];
  for (let i = 0; i < view.items.length; i++) {
    if (byte >= view.items[i].from && byte < view.items[i].to) {
      return i;
    }
  }
  return -1;
}

function show(next) {
  stage = next;
  selected = -1;
  const view = stages[stage];
  meterBytes.textContent = (view.hex.length / 2).toString();
  meterFields.textContent = String(view.items.length);
  meterWhat.textContent = view.what;
  paintHex();
  paintFields();
  clearHighlight();
  note.textContent = "Pick a byte, or a field; the other side follows.";
  for (const button of document.querySelectorAll("[data-stage]")) {
    button.setAttribute("aria-pressed", button.dataset.stage === stage ? "true" : "false");
  }
}

document.addEventListener("click", (event) => {
  const stageButton = event.target.closest("[data-stage]");
  if (stageButton) {
    show(stageButton.dataset.stage);
    return;
  }
  const byte = event.target.closest(".byte");
  if (byte) {
    const index = fieldAt(Number(byte.dataset.at));
    if (index >= 0) {
      selected = index;
      highlight(index);
    }
    return;
  }
  const row = event.target.closest(".fieldrow");
  if (row) {
    selected = Number(row.dataset.index);
    highlight(selected);
  }
});

document.addEventListener("mouseover", (event) => {
  const byte = event.target.closest(".byte");
  if (!byte) {
    return;
  }
  const index = fieldAt(Number(byte.dataset.at));
  if (index >= 0 && index !== selected) {
    clearHighlight();
    const item = stages[stage].items[index];
    for (let at = item.from; at < item.to && at < spans.length; at++) {
      spans[at].classList.add("is-field");
    }
    const row = fieldsBox.children[index];
    if (row) {
      row.classList.add("is-on");
    }
  }
});

show("header");
