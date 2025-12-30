import "./static/basecoat.js";
import "./static/dropdown-menu-v2.js";

/**
 * @type {Record<string, (element: Element) => void>}
 */
const initFuncs = {
  "data-hide-side-pane": function initHideSidePane(targetElement) {
    targetElement.addEventListener("click", function hideSidePane() {
      const sidePane = document.getElementById("side-pane");
      if (!sidePane) {
        return;
      }
      sidePane.classList.add("hidden");
    });
  },
  "data-show-side-pane": function initShowSidePane(targetElement) {
    targetElement.addEventListener("click", function showSidePane() {
      const sidePane = document.getElementById("side-pane");
      if (!sidePane) {
        return;
      }
      sidePane.classList.remove("hidden");
    });
  },
  "data-go-back": function initGoBack(targetElement) {
    if (targetElement.tagName != "A") {
      return;
    }
    targetElement.addEventListener("click", function goBack(event) {
      if (!(event instanceof PointerEvent)) {
        return;
      }
      if (document.referrer && history.length > 2 && !event.ctrlKey && !event.metaKey) {
        event.preventDefault();
        history.back();
      }
    });
  },
};

const attributeNames = Object.keys(initFuncs);
let selector = "";
for (let i = 0; i < attributeNames.length; i++) {
  if (i > 0) {
    selector += ", ";
  }
  selector += `[${attributeNames[i]}]`
}
for (const targetElement of document.querySelectorAll(selector)) {
  for (const attributeName of attributeNames) {
    if (targetElement.hasAttribute(attributeName) && targetElement.getAttribute(attributeName) != "initialized") {
      try {
        initFuncs[attributeName](targetElement);
      } catch (e) {
        console.error(e);
      }
      targetElement.setAttribute(attributeName, "initialized");
    }
  }
}
const observer = new MutationObserver(function(mutationRecords) {
  for (const mutationRecord of mutationRecords) {
    if (mutationRecord.type != "childList") {
      continue;
    }
    for (const addedElement of mutationRecord.addedNodes) {
      if (!(addedElement instanceof Element)) {
        continue;
      }
      for (const attributeName of attributeNames) {
        if (addedElement.hasAttribute(attributeName) && addedElement.getAttribute(attributeName) != "initialized") {
          try {
            initFuncs[attributeName](addedElement);
          } catch (e) {
            console.error(e);
          }
          addedElement.setAttribute(attributeName, "initialized");
        }
      }
      for (const targetElement of addedElement.querySelectorAll(selector)) {
        for (const attributeName of attributeNames) {
          if (targetElement.hasAttribute(attributeName) && targetElement.getAttribute(attributeName) != "initialized") {
            try {
              initFuncs[attributeName](targetElement);
            } catch (e) {
              console.error(e);
            }
            targetElement.setAttribute(attributeName, "initialized");
          }
        }
      }
    }
  }
});
observer.observe(document.body, {
  childList: true,
  subtree: true,
});

document.addEventListener("click", function hideSidePaneOnClickOutside(event) {
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

function humanReadableFileSize(size) {
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
