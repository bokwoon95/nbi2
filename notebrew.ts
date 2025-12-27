import "./static/basecoat.js";
import "./static/dropdown-menu-v2.js";

const sidePane = document.getElementById("side-pane");
if (!sidePane) {
  throw new Error("#side-pane not found");
}
const notSidePane = document.getElementById("not-side-pane");
if (!notSidePane) {
  throw new Error("#not-side-pane not found");
}
window.addEventListener("click", function(event) {
  if (window.matchMedia("(min-width: 64rem)" /* tailwind lg breakpoint */).matches) {
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
for (const dataHideSidePane of document.querySelectorAll("[data-hide-side-pane]")) {
  dataHideSidePane.addEventListener("click", function() {
    sidePane.classList.add("hidden");
  });
}
for (const dataShowSidePane of document.querySelectorAll("[data-show-side-pane]")) {
  dataShowSidePane.addEventListener("click", function() {
    sidePane.classList.remove("hidden");
  });
}

const hamburgerMenuBtn = document.getElementById("hamburger-menu-btn");
const hamburgerMenuIcon = document.getElementById("hamburger-menu-icon");
const menuPane = document.getElementById("menu-pane");
const notMenuPane = document.getElementById("not-menu-pane");
if (hamburgerMenuBtn && hamburgerMenuIcon && sidePane && notMenuPane) {
  hamburgerMenuBtn.addEventListener("click", function() {
    if (hamburgerMenuIcon.classList.contains("open")) {
      hamburgerMenuIcon.classList.remove("open");
      sidePane.classList.add("hidden");
    } else {
      hamburgerMenuIcon.classList.add("open");
      sidePane.classList.remove("hidden");
    }
  });
  notMenuPane.addEventListener("click", function() {
    if (hamburgerMenuIcon.classList.contains("open")) {
      hamburgerMenuIcon.classList.remove("open");
      sidePane.classList.add("hidden");
    }
  });
}

for (const dataClickEventStopPropagation of document.querySelectorAll("[data-click-event-stop-propagation]")) {
  dataClickEventStopPropagation.addEventListener("click", function(event) {
    event.stopPropagation();
  });
}

for (const dataDismissAlert of document.querySelectorAll("[data-dismiss-alert]")) {
  dataDismissAlert.addEventListener("click", function() {
    let parentElement = dataDismissAlert.parentElement;
    while (parentElement != null) {
      const role = parentElement.getAttribute("role");
      if (role != "alert") {
        parentElement = parentElement.parentElement;
        continue;
      }
      parentElement.style.transition = "opacity 100ms linear";
      parentElement.style.opacity = "0";
      setTimeout(function() {
        if (parentElement) {
          parentElement.style.display = "none"
        }
      }, 100);
      return;
    }
  });
}

for (const dataGoBack of document.querySelectorAll("[data-go-back]")) {
  if (dataGoBack.tagName != "A") {
    continue;
  }
  dataGoBack.addEventListener("click", function(event) {
    if (!(event instanceof PointerEvent)) {
      return;
    }
    if (document.referrer && history.length > 2 && !event.ctrlKey && !event.metaKey) {
      event.preventDefault();
      history.back();
    }
  });
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
