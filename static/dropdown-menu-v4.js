(() => {
  const initDropdownMenu = (dropdownMenuComponent) => {
    const trigger = dropdownMenuComponent.querySelector(':scope > button');
    const popover = dropdownMenuComponent.querySelector(':scope > [data-popover]');
    const menu = popover?.querySelector('[role="menu"]');
    const supportsManualPopover = typeof popover?.showPopover === 'function' && typeof popover?.hidePopover === 'function';
    if (supportsManualPopover) {
      popover.setAttribute('popover', 'manual');
      popover.style.position = 'fixed'; // keep popover anchored to viewport while in top layer
      popover.style.inset = 'auto';
      popover.style.transform = 'none';
    }
    if (!trigger || !menu || !popover) {
      const missing = [];
      if (!trigger) missing.push('trigger');
      if (!menu) missing.push('menu');
      if (!popover) missing.push('popover');
      console.error(`Dropdown menu initialisation failed. Missing element(s): ${missing.join(', ')}`, dropdownMenuComponent);
      return;
    }

    let positionFrame = 0;
    let menuItems = [];
    let activeIndex = -1;

    const isMobileLike = () => window.matchMedia('(hover: none), (pointer: coarse)').matches;
    const submenuParents = () => Array.from(menu.querySelectorAll('[role="menuitem"][aria-haspopup="menu"]'));

    const closeAllSubmenus = () => {
      submenuParents().forEach((parent) => {
        const submenu = parent.querySelector(':scope > [role="menu"]');
        parent.setAttribute('aria-expanded', 'false');
        submenu?.setAttribute('aria-hidden', 'true');
      });
    };

    const openSubmenu = (parent) => {
      const submenu = parent.querySelector(':scope > [role="menu"]');
      if (!submenu) return;
      closeAllSubmenus();
      parent.setAttribute('aria-expanded', 'true');
      submenu.setAttribute('aria-hidden', 'false');
    };

    const setActiveItem = (index) => {
      if (activeIndex > -1 && menuItems[activeIndex]) {
        menuItems[activeIndex].classList.remove('active');
      }
      activeIndex = index;
      if (activeIndex > -1 && menuItems[activeIndex]) {
        const activeItem = menuItems[activeIndex];
        activeItem.classList.add('active');
        if (activeItem.id) trigger.setAttribute('aria-activedescendant', activeItem.id);
        else trigger.removeAttribute('aria-activedescendant');
      } else {
        trigger.removeAttribute('aria-activedescendant');
      }
    };

    const closePopover = (focusOnTrigger = true) => {
      if (trigger.getAttribute('aria-expanded') === 'false') return;
      trigger.setAttribute('aria-expanded', 'false');
      trigger.removeAttribute('aria-activedescendant');
      popover.setAttribute('aria-hidden', 'true');
      if (supportsManualPopover && popover.matches(':popover-open')) popover.hidePopover();
      closeAllSubmenus();
      if (focusOnTrigger) trigger.focus();
      if (supportsManualPopover) cancelAnimationFrame(positionFrame);
      setActiveItem(-1);
    };

    const updatePosition = () => {
      if (!supportsManualPopover || trigger.getAttribute('aria-expanded') !== 'true') return;
      const rect = trigger.getBoundingClientRect();
      const visualViewport = window.visualViewport;
      const viewportLeft = visualViewport ? visualViewport.offsetLeft : 0;
      const viewportTop = visualViewport ? visualViewport.offsetTop : 0;
      const viewportWidth = visualViewport ? visualViewport.width : window.innerWidth;
      const viewportHeight = visualViewport ? visualViewport.height : window.innerHeight;
      const minLeft = viewportLeft + 8;
      const minTop = viewportTop + 8;
      const maxLeft = viewportLeft + viewportWidth - 8;
      const maxTop = viewportTop + viewportHeight - 8;
      let left = rect.left + viewportLeft;
      let top = rect.bottom + viewportTop;
      const width = popover.offsetWidth;
      const height = popover.offsetHeight;
      if (left + width > maxLeft) left = Math.max(minLeft, maxLeft - width);
      if (left < minLeft) left = minLeft;
      if (top + height > maxTop) {
        const aboveTop = rect.top + viewportTop - height;
        const spaceBelow = maxTop - (rect.bottom + viewportTop);
        const spaceAbove = rect.top + viewportTop - minTop;
        if (aboveTop >= minTop || spaceAbove > spaceBelow) top = aboveTop;
        else top = Math.max(minTop, maxTop - height);
      }
      if (top < minTop) top = minTop;
      popover.style.left = `${Math.round(left)}px`;
      popover.style.top = `${Math.round(top)}px`;
    };

    const openPopover = (initialSelection = false) => {
      document.dispatchEvent(new CustomEvent('basecoat:popover', { detail: { source: dropdownMenuComponent } }));
      trigger.setAttribute('aria-expanded', 'true');
      popover.setAttribute('aria-hidden', 'false');
      if (supportsManualPopover) {
        popover.showPopover();
        updatePosition();
        const tick = () => {
          if (trigger.getAttribute('aria-expanded') !== 'true') return;
          updatePosition();
          positionFrame = requestAnimationFrame(tick);
        };
        tick();
      }
      closeAllSubmenus();
      menuItems = Array.from(menu.querySelectorAll('[role="menuitem"]')).filter((item) => !item.hasAttribute('disabled') && item.getAttribute('aria-disabled') !== 'true');
      if (menuItems.length > 0 && initialSelection) {
        if (initialSelection === 'first') setActiveItem(0);
        if (initialSelection === 'last') setActiveItem(menuItems.length - 1);
      }
    };

    trigger.addEventListener('click', () => {
      if (trigger.getAttribute('aria-expanded') === 'true') closePopover();
      else openPopover(false);
    });

    dropdownMenuComponent.addEventListener('keydown', (event) => {
      const isExpanded = trigger.getAttribute('aria-expanded') === 'true';

      if (event.key === 'Escape') {
        if (isExpanded) closePopover();
        return;
      }
      if (!isExpanded) {
        if (['Enter', ' '].includes(event.key)) {
          event.preventDefault();
          openPopover(false);
        } else if (event.key === 'ArrowDown') {
          event.preventDefault();
          openPopover('first');
        } else if (event.key === 'ArrowUp') {
          event.preventDefault();
          openPopover('last');
        }
        return;
      }
      if (menuItems.length === 0) return;

      let nextIndex = activeIndex;
      switch (event.key) {
        case 'ArrowDown':
          event.preventDefault();
          nextIndex = activeIndex === -1 ? 0 : Math.min(activeIndex + 1, menuItems.length - 1);
          break;
        case 'ArrowUp':
          event.preventDefault();
          nextIndex = activeIndex === -1 ? menuItems.length - 1 : Math.max(activeIndex - 1, 0);
          break;
        case 'Home':
          event.preventDefault();
          nextIndex = 0;
          break;
        case 'End':
          event.preventDefault();
          nextIndex = menuItems.length - 1;
          break;
        case 'ArrowRight': {
          const item = menuItems[activeIndex];
          if (!item) break;
          const submenu = item.querySelector(':scope > [role="menu"]');
          if (submenu) {
            event.preventDefault();
            openSubmenu(item);
          }
          break;
        }
        case 'ArrowLeft': {
          const item = menuItems[activeIndex];
          if (!item) break;
          const parentMenu = item.closest('[role="menu"]');
          if (parentMenu && parentMenu !== menu) {
            const parentItem = parentMenu.closest('[role="menuitem"][aria-haspopup="menu"]');
            if (parentItem) {
              event.preventDefault();
              parentItem.setAttribute('aria-expanded', 'false');
              parentMenu.setAttribute('aria-hidden', 'true');
            }
          }
          break;
        }
        case 'Enter':
        case ' ': {
          const item = menuItems[activeIndex];
          if (!item) return;
          const submenu = item.querySelector(':scope > [role="menu"]');
          event.preventDefault();
          if (submenu) openSubmenu(item);
          else closePopover();
          return;
        }
      }

      if (nextIndex !== activeIndex) {
        setActiveItem(nextIndex);
      }
    });

    menu.addEventListener('mousemove', (event) => {
      const item = event.target.closest('[role="menuitem"]');
      if (!item || !menuItems.includes(item)) return;
      const index = menuItems.indexOf(item);
      if (index !== activeIndex) setActiveItem(index);
      if (!isMobileLike() && item.getAttribute('aria-haspopup') === 'menu') {
        openSubmenu(item);
      }
    });

    menu.addEventListener('mouseleave', () => {
      setActiveItem(-1);
    });

    menu.addEventListener('click', (event) => {
      const item = event.target.closest('[role="menuitem"]');
      if (!item) return;
      const submenu = item.querySelector(':scope > [role="menu"]');
      if (submenu) {
        event.preventDefault();
        if (item.getAttribute('aria-expanded') === 'true') {
          item.setAttribute('aria-expanded', 'false');
          submenu.setAttribute('aria-hidden', 'true');
        } else {
          openSubmenu(item);
        }
        return;
      }
      closePopover();
    });

    document.addEventListener('click', (event) => {
      if (!dropdownMenuComponent.contains(event.target)) closePopover(false);
    });

    document.addEventListener('basecoat:popover', (event) => {
      if (event.detail.source !== dropdownMenuComponent) closePopover(false);
    });

    dropdownMenuComponent.dataset.dropdownMenuInitialized = true;
    dropdownMenuComponent.dispatchEvent(new CustomEvent('basecoat:initialized'));
  };

  if (window.basecoat) {
    window.basecoat.register('dropdown-menu', '.dropdown-menu:not([data-dropdown-menu-initialized])', initDropdownMenu);
  }
})();
