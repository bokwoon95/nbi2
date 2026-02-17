/**
 * @type {Record<string, (element: Element) => void>}
 */
const initFuncs = {
  "data-toggle-sidebar": function(targetElement) {
    targetElement.addEventListener("click", function() {
      document.dispatchEvent(new Event('basecoat:sidebar'));
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
