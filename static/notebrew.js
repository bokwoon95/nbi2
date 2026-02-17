import "./basecoat.js";
import "./sidebar.js";
import "./dropdown-menu-v4.js";

for (const element of document.querySelectorAll("[data-toggle-sidebar]")) {
  element.addEventListener("click", function() {
    document.dispatchEvent(new Event('basecoat:sidebar'));
  });
}

for (const element of document.querySelectorAll("[data-go-back]")) {
  if (element.tagName != "A") {
    continue;
  }
  element.addEventListener("click", function goBack(event) {
    if (!(event instanceof PointerEvent)) {
      return;
    }
    if (document.referrer && history.length > 2 && !event.ctrlKey && !event.metaKey) {
      event.preventDefault();
      history.back();
    }
  });
}

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
