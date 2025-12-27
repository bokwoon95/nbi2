(() => {
  // static/basecoat.js
  (() => {
    const componentRegistry = {};
    let observer = null;
    const registerComponent = (name, selector, initFunction) => {
      componentRegistry[name] = {
        selector,
        init: initFunction
      };
    };
    const initComponent = (element, componentName) => {
      const component = componentRegistry[componentName];
      if (!component) return;
      try {
        component.init(element);
      } catch (error) {
        console.error(`Failed to initialize ${componentName}:`, error);
      }
    };
    const initAllComponents = () => {
      Object.entries(componentRegistry).forEach(([name, { selector, init }]) => {
        document.querySelectorAll(selector).forEach(init);
      });
    };
    const initNewComponents = (node) => {
      if (node.nodeType !== Node.ELEMENT_NODE) return;
      Object.entries(componentRegistry).forEach(([name, { selector, init }]) => {
        if (node.matches(selector)) {
          init(node);
        }
        node.querySelectorAll(selector).forEach(init);
      });
    };
    const startObserver = () => {
      if (observer) return;
      observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          mutation.addedNodes.forEach(initNewComponents);
        });
      });
      observer.observe(document.body, { childList: true, subtree: true });
    };
    const stopObserver = () => {
      if (observer) {
        observer.disconnect();
        observer = null;
      }
    };
    const reinitComponent = (componentName) => {
      const component = componentRegistry[componentName];
      if (!component) {
        console.warn(`Component '${componentName}' not found in registry`);
        return;
      }
      const flag = `data-${componentName}-initialized`;
      document.querySelectorAll(`[${flag}]`).forEach((el) => {
        el.removeAttribute(flag);
      });
      document.querySelectorAll(component.selector).forEach(component.init);
    };
    const reinitAll = () => {
      Object.entries(componentRegistry).forEach(([name, { selector }]) => {
        const flag = `data-${name}-initialized`;
        document.querySelectorAll(`[${flag}]`).forEach((el) => {
          el.removeAttribute(flag);
        });
      });
      initAllComponents();
    };
    window.basecoat = {
      register: registerComponent,
      init: reinitComponent,
      initAll: reinitAll,
      start: startObserver,
      stop: stopObserver
    };
    document.addEventListener("DOMContentLoaded", () => {
      initAllComponents();
      startObserver();
    });
  })();

  // static/dropdown-menu-v2.js
  (() => {
    const initDropdownMenu = (dropdownMenuComponent) => {
      const trigger = dropdownMenuComponent.querySelector(":scope > button");
      const popover = dropdownMenuComponent.querySelector(":scope > [data-popover]");
      const menu = popover.querySelector('[role="menu"]');
      const supportsManualPopover = typeof popover.showPopover === "function" && typeof popover.hidePopover === "function";
      if (supportsManualPopover) {
        popover.setAttribute("popover", "manual");
        popover.style.position = "fixed";
        popover.style.inset = "auto";
        popover.style.transform = "none";
      }
      let positionFrame = 0;
      const updatePosition = () => {
        if (!supportsManualPopover || trigger.getAttribute("aria-expanded") !== "true") return;
        const rect = trigger.getBoundingClientRect();
        let left = rect.left;
        let top = rect.bottom;
        const viewportWidth = document.documentElement.clientWidth;
        const viewportHeight = document.documentElement.clientHeight;
        const width = popover.offsetWidth;
        const height = popover.offsetHeight;
        if (left + width > viewportWidth - 8) left = Math.max(8, viewportWidth - width - 8);
        if (left < 8) left = 8;
        if (top + height > viewportHeight - 8 && rect.top - height >= 8) top = rect.top - height;
        if (top + height > viewportHeight - 8) top = Math.max(8, viewportHeight - height - 8);
        if (top < 8) top = 8;
        popover.style.left = `${Math.round(left)}px`;
        popover.style.top = `${Math.round(top)}px`;
      };
      const startAutoPosition = () => {
        if (!supportsManualPopover) return;
        cancelAnimationFrame(positionFrame);
        const tick = () => {
          if (trigger.getAttribute("aria-expanded") !== "true") return;
          updatePosition();
          positionFrame = requestAnimationFrame(tick);
        };
        tick();
      };
      const stopAutoPosition = () => {
        if (!supportsManualPopover) return;
        cancelAnimationFrame(positionFrame);
        positionFrame = 0;
      };
      if (!trigger || !menu || !popover) {
        const missing = [];
        if (!trigger) missing.push("trigger");
        if (!menu) missing.push("menu");
        if (!popover) missing.push("popover");
        console.error(`Dropdown menu initialisation failed. Missing element(s): ${missing.join(", ")}`, dropdownMenuComponent);
        return;
      }
      let menuItems = [];
      let activeIndex = -1;
      const closePopover = (focusOnTrigger = true) => {
        if (trigger.getAttribute("aria-expanded") === "false") return;
        trigger.setAttribute("aria-expanded", "false");
        trigger.removeAttribute("aria-activedescendant");
        popover.setAttribute("aria-hidden", "true");
        if (supportsManualPopover && popover.matches(":popover-open")) popover.hidePopover();
        if (focusOnTrigger) {
          trigger.focus();
        }
        stopAutoPosition();
        setActiveItem(-1);
      };
      const openPopover = (initialSelection = false) => {
        document.dispatchEvent(new CustomEvent("basecoat:popover", {
          detail: { source: dropdownMenuComponent }
        }));
        trigger.setAttribute("aria-expanded", "true");
        popover.setAttribute("aria-hidden", "false");
        if (supportsManualPopover) {
          popover.showPopover();
          updatePosition();
          startAutoPosition();
        }
        menuItems = Array.from(menu.querySelectorAll('[role^="menuitem"]')).filter(
          (item) => !item.hasAttribute("disabled") && item.getAttribute("aria-disabled") !== "true"
        );
        if (menuItems.length > 0 && initialSelection) {
          if (initialSelection === "first") {
            setActiveItem(0);
          } else if (initialSelection === "last") {
            setActiveItem(menuItems.length - 1);
          }
        }
      };
      const setActiveItem = (index) => {
        if (activeIndex > -1 && menuItems[activeIndex]) {
          menuItems[activeIndex].classList.remove("active");
        }
        activeIndex = index;
        if (activeIndex > -1 && menuItems[activeIndex]) {
          const activeItem = menuItems[activeIndex];
          activeItem.classList.add("active");
          trigger.setAttribute("aria-activedescendant", activeItem.id);
        } else {
          trigger.removeAttribute("aria-activedescendant");
        }
      };
      trigger.addEventListener("click", () => {
        const isExpanded = trigger.getAttribute("aria-expanded") === "true";
        if (isExpanded) {
          closePopover();
        } else {
          openPopover(false);
        }
      });
      dropdownMenuComponent.addEventListener("keydown", (event) => {
        const isExpanded = trigger.getAttribute("aria-expanded") === "true";
        if (event.key === "Escape") {
          if (isExpanded) closePopover();
          return;
        }
        if (!isExpanded) {
          if (["Enter", " "].includes(event.key)) {
            event.preventDefault();
            openPopover(false);
          } else if (event.key === "ArrowDown") {
            event.preventDefault();
            openPopover("first");
          } else if (event.key === "ArrowUp") {
            event.preventDefault();
            openPopover("last");
          }
          return;
        }
        if (menuItems.length === 0) return;
        let nextIndex = activeIndex;
        switch (event.key) {
          case "ArrowDown":
            event.preventDefault();
            nextIndex = activeIndex === -1 ? 0 : Math.min(activeIndex + 1, menuItems.length - 1);
            break;
          case "ArrowUp":
            event.preventDefault();
            nextIndex = activeIndex === -1 ? menuItems.length - 1 : Math.max(activeIndex - 1, 0);
            break;
          case "Home":
            event.preventDefault();
            nextIndex = 0;
            break;
          case "End":
            event.preventDefault();
            nextIndex = menuItems.length - 1;
            break;
          case "Enter":
          case " ":
            event.preventDefault();
            menuItems[activeIndex]?.click();
            closePopover();
            return;
        }
        if (nextIndex !== activeIndex) {
          setActiveItem(nextIndex);
        }
      });
      menu.addEventListener("mousemove", (event) => {
        const menuItem = event.target.closest('[role^="menuitem"]');
        if (menuItem && menuItems.includes(menuItem)) {
          const index = menuItems.indexOf(menuItem);
          if (index !== activeIndex) {
            setActiveItem(index);
          }
        }
      });
      menu.addEventListener("mouseleave", () => {
        setActiveItem(-1);
      });
      menu.addEventListener("click", (event) => {
        if (event.target.closest('[role^="menuitem"]')) {
          closePopover();
        }
      });
      document.addEventListener("click", (event) => {
        if (!dropdownMenuComponent.contains(event.target)) {
          closePopover();
        }
      });
      document.addEventListener("basecoat:popover", (event) => {
        if (event.detail.source !== dropdownMenuComponent) {
          closePopover(false);
        }
      });
      dropdownMenuComponent.dataset.dropdownMenuInitialized = true;
      dropdownMenuComponent.dispatchEvent(new CustomEvent("basecoat:initialized"));
    };
    if (window.basecoat) {
      window.basecoat.register("dropdown-menu", ".dropdown-menu:not([data-dropdown-menu-initialized])", initDropdownMenu);
    }
  })();

  // notebrew.ts
  var sidePane = document.getElementById("side-pane");
  if (!sidePane) {
    throw new Error("#side-pane not found");
  }
  var notSidePane = document.getElementById("not-side-pane");
  if (!notSidePane) {
    throw new Error("#not-side-pane not found");
  }
  window.addEventListener("click", function(event) {
    console.log("--------------------------------------------------------------------------------");
    console.log("1");
    if (window.matchMedia(
      "(min-width: 64rem)"
      /* tailwind lg breakpoint */
    ).matches) {
      return;
    }
    console.log("2");
    if (sidePane.classList.contains("hidden")) {
      return;
    }
    console.log("3");
    for (let element = event.target; element instanceof Element; element = element.parentElement) {
      if (element.id == "side-pane") {
        return;
      }
      if (element.hasAttribute("data-show-side-pane")) {
        return;
      }
    }
    console.log("4");
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
  var hamburgerMenuBtn = document.getElementById("hamburger-menu-btn");
  var hamburgerMenuIcon = document.getElementById("hamburger-menu-icon");
  var menuPane = document.getElementById("menu-pane");
  var notMenuPane = document.getElementById("not-menu-pane");
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
            parentElement.style.display = "none";
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
})();
