import "./static/basecoat.js";
import "./static/dropdown-menu-v2.js";

document.addEventListener("click", function hideSidePane(event) {
  if (window.matchMedia("(min-width: 64rem)" /* tailwind lg breakpoint */).matches) {
    return;
  }
  const sidePane = document.getElementById("side-pane");
  if (!sidePane) {
    return;
  }
  if (sidePane.classList.contains("hidden")) {
    return;
  }
  for (let element = event.target; element instanceof Element; element = element.parentElement) {
    if (element.id == "side-pane") {
      return;
    }
    if (element.hasAttribute("data-show-side-pane")) {
      return;
    }
  }
  sidePane.classList.add("hidden");
});

globalThis.initFuncs = [
  (function() {
    const hideSidePaneTargets = new WeakSet();
    const showSidePaneTargets = new WeakSet();
    const goBackTargets = new WeakSet();
    return function init() {
      const sidePane = document.getElementById("side-pane");
      if (!sidePane) {
        throw new Error("#side-pane not found");
      }
      const notSidePane = document.getElementById("not-side-pane");
      if (!notSidePane) {
        throw new Error("#not-side-pane not found");
      }
      for (const eventTarget of document.querySelectorAll("[data-hide-side-pane]")) {
        if (hideSidePaneTargets.has(eventTarget)) {
          continue;
        }
        hideSidePaneTargets.add(eventTarget);
        eventTarget.addEventListener("click", function() {
          sidePane.classList.add("hidden");
        });
      }
      for (const eventTarget of document.querySelectorAll("[data-show-side-pane]")) {
        if (showSidePaneTargets.has(eventTarget)) {
          continue;
        }
        showSidePaneTargets.add(eventTarget);
        eventTarget.addEventListener("click", function() {
          sidePane.classList.remove("hidden");
        });
      }
      for (const eventTarget of document.querySelectorAll("[data-go-back]")) {
        if (goBackTargets.has(eventTarget)) {
          continue;
        }
        goBackTargets.add(eventTarget);
        if (eventTarget.tagName != "A") {
          continue;
        }
        eventTarget.addEventListener("click", function(event) {
          if (!(event instanceof PointerEvent)) {
            return;
          }
          if (document.referrer && history.length > 2 && !event.ctrlKey && !event.metaKey) {
            event.preventDefault();
            history.back();
          }
        });
      }
    }
  })(),
];

for (const fn of globalThis.initFuncs) {
  if (typeof fn == "function") {
    fn();
  }
}

function humanReadableFileSize(size: number) {
  if (size < 0) {
    return "";
  }
  const unit = 1000;
  if (size < unit) {
    return size.toString() + " B";
  }
  let div = unit;
  let exp = 0;
  for (let n = size / unit; n >= unit; n /= unit) {
    div *= unit;
    exp++;
  }
  return (size / div).toFixed(1) + " " + ["kB", "MB", "GB", "TB", "PB", "EB"][exp];
}
