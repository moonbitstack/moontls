// The two demonstrations. Both call the library built to JavaScript — `docs/engine/moontls.js`,
// compiled from `src/examples/browser` by the docs workflow — so what the page shows is this
// library's own reading of the octets, not a second implementation of it written in JavaScript.

import { sample_hello, parse_hello, handshake } from "../../engine/moontls.js";

// ---------------------------------------------------------------- the ClientHello

const field = document.querySelector("[data-hello-hex]");
const parseOut = document.querySelector("[data-hello-out]");
const parseStatus = document.querySelector("[data-hello-status]");
const parseButton = document.querySelector("[data-hello-parse]");
const sampleButton = document.querySelector("[data-hello-sample]");

function renderHello(hex) {
  const body = parseOut.querySelector(".body");
  body.replaceChildren();
  const rows = parse_hello(hex).split("\n").filter(Boolean);
  const list = document.createElement("dl");
  list.className = "fields";
  let count = 0;
  for (const line of rows) {
    const [kind, a = "", b = "", c = ""] = line.split("\t");
    if (kind === "title") {
      parseStatus.textContent = `${a} · ${b} · ${c}`;
      continue;
    }
    const row = document.createElement("div");
    row.className = "fact";
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    if (kind === "error") {
      row.classList.add("bad");
      dt.textContent = "refused";
      dd.textContent = a;
      parseStatus.textContent = "not a ClientHello";
    } else if (kind === "suite") {
      dt.textContent = a;
      dd.textContent = b;
    } else {
      dt.textContent = a;
      dd.textContent = b;
      if (c) {
        const note = document.createElement("span");
        note.className = "note";
        note.textContent = c;
        dd.append(note);
      }
    }
    row.append(dt, dd);
    list.append(row);
    count += 1;
  }
  body.append(list);
  if (parseStatus.textContent === "") parseStatus.textContent = `${count} fields`;
}

function parse() {
  renderHello(field.value.trim());
}

sampleButton?.addEventListener("click", () => {
  field.value = sample_hello();
  parse();
});

parseButton?.addEventListener("click", parse);

field?.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
    event.preventDefault();
    parse();
  }
});

if (field) {
  const sample = sample_hello();
  field.value = sample;
  parse();
}

// ---------------------------------------------------------------- the handshake

const traceOut = document.querySelector("[data-trace-out]");
const traceStatus = document.querySelector("[data-trace-status]");
const traceButton = document.querySelector("[data-trace-run]");
const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;

function renderTrace() {
  const rows = handshake().split("\n").filter(Boolean);
  const box = traceOut.querySelector(".body");
  box.replaceChildren();
  const trace = document.createElement("div");
  trace.className = "trace";
  let last = null;
  traceStatus.textContent = "running";
  rows.forEach((line, index) => {
    const [kind, a = "", b = "", c = "", d = "", e = ""] = line.split("\t");
    let node;
    if (kind === "step") {
      node = document.createElement("div");
      node.className = "row";
      const n = document.createElement("span");
      n.className = "n";
      n.textContent = a;
      const arrow = document.createElement("span");
      arrow.className = b === "->" ? "arrow" : "arrow back";
      arrow.textContent = b;
      const name = document.createElement("span");
      name.className = "name";
      name.textContent = c;
      const size = document.createElement("span");
      size.className = "size";
      size.textContent = d;
      const level = document.createElement("span");
      level.className = "level";
      level.textContent = e;
      node.append(n, arrow, name, size, level);
    } else if (kind === "keys") {
      node = document.createElement("div");
      node.className = "keys";
      node.textContent = `${a} has ${b}`;
    } else if (kind === "done") {
      node = document.createElement("div");
      node.className = "done";
      node.textContent = a;
      traceStatus.textContent = "settled";
    } else if (kind === "error") {
      node = document.createElement("div");
      node.className = "done";
      node.textContent = a;
      traceStatus.textContent = "refused";
    }
    if (!node) return;
    if (calm) {
      trace.append(node);
    } else {
      node.style.opacity = "0";
      node.style.transform = "translateY(3px)";
      node.style.transition = "opacity 220ms ease, transform 220ms ease";
      trace.append(node);
      setTimeout(() => {
        node.style.opacity = "1";
        node.style.transform = "none";
      }, index * 55);
    }
    last = node;
  });
  box.append(trace);
  last?.scrollIntoView({ block: "nearest" });
}

traceButton?.addEventListener("click", () => {
  traceButton.disabled = true;
  traceStatus.textContent = "running";
  requestAnimationFrame(() => {
    renderTrace();
    traceButton.disabled = false;
  });
});

// The walk is instant, so the panel has something in it before anyone asks: the button is there to
// watch it happen again.
if (traceOut) renderTrace();
