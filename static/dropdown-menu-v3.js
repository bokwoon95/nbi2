(() => {
  const initDropdownMenu = (dropdownMenuComponent) => {
    const trigger = dropdownMenuComponent.querySelector(':scope > button');
    const popover = dropdownMenuComponent.querySelector(':scope > [data-popover]');
    const menu = popover.querySelector('[role="menu"]');
    const supportsManualPopover = typeof popover.showPopover === 'function' && typeof popover.hidePopover === 'function';
    if (supportsManualPopover) {
      popover.setAttribute('popover', 'manual');
      popover.style.position = 'fixed'; // keep the popover anchored to the viewport while in the top layer
      popover.style.inset = 'auto';
      popover.style.transform = 'none';
    }
    let positionFrame = 0;
    const updatePosition = () => {
      if (!supportsManualPopover || trigger.getAttribute('aria-expanded') !== 'true') return;
      const rect = trigger.getBoundingClientRect();
      // On iOS Safari, the visual viewport tracks URL bar expansion/collapse while
      // documentElement metrics may stay tied to a different viewport height.
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
      if (top + height > maxTop && rect.top + viewportTop - height >= minTop) top = rect.top + viewportTop - height;
      if (top + height > maxTop) top = Math.max(minTop, maxTop - height);
      if (top < minTop) top = minTop;
      popover.style.left = `${Math.round(left)}px`;
      popover.style.top = `${Math.round(top)}px`;
    };
    const startAutoPosition = () => {
      if (!supportsManualPopover) return;
      cancelAnimationFrame(positionFrame);
      const tick = () => {
        if (trigger.getAttribute('aria-expanded') !== 'true') return;
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
      if (!trigger) missing.push('trigger');
      if (!menu) missing.push('menu');
      if (!popover) missing.push('popover');
      console.error(`Dropdown menu initialisation failed. Missing element(s): ${missing.join(', ')}`, dropdownMenuComponent);
      return;
    }

    let menuItems = [];
    let activeIndex = -1;

    const closePopover = (focusOnTrigger = true) => {
      if (trigger.getAttribute('aria-expanded') === 'false') return;
      trigger.setAttribute('aria-expanded', 'false');
      trigger.removeAttribute('aria-activedescendant');
      popover.setAttribute('aria-hidden', 'true');
      if (supportsManualPopover && popover.matches(':popover-open')) popover.hidePopover();
      
      if (focusOnTrigger) {
        trigger.focus();
      }
      
      stopAutoPosition();
      setActiveItem(-1);
    };

    const openPopover = (initialSelection = false) => {
      document.dispatchEvent(new CustomEvent('basecoat:popover', {
        detail: { source: dropdownMenuComponent }
      }));
      
      trigger.setAttribute('aria-expanded', 'true');
      popover.setAttribute('aria-hidden', 'false');
      if (supportsManualPopover) {
        popover.showPopover();
        updatePosition();
        startAutoPosition();
      }
      menuItems = Array.from(menu.querySelectorAll('[role^="menuitem"]')).filter(item => 
        !item.hasAttribute('disabled') && 
        item.getAttribute('aria-disabled') !== 'true'
      );
      
      if (menuItems.length > 0 && initialSelection) {
        if (initialSelection === 'first') {
          setActiveItem(0);
        } else if (initialSelection === 'last') {
          setActiveItem(menuItems.length - 1);
        }
      }
    };

    const setActiveItem = (index) => {
      if (activeIndex > -1 && menuItems[activeIndex]) {
        menuItems[activeIndex].classList.remove('active');
      }
      activeIndex = index;
      if (activeIndex > -1 && menuItems[activeIndex]) {
        const activeItem = menuItems[activeIndex];
        activeItem.classList.add('active');
        trigger.setAttribute('aria-activedescendant', activeItem.id);
      } else {
        trigger.removeAttribute('aria-activedescendant');
      }
    };

    trigger.addEventListener('click', () => {
      const isExpanded = trigger.getAttribute('aria-expanded') === 'true';
      if (isExpanded) {
        closePopover();
      } else {
        openPopover(false);
      }
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
        case 'Enter':
        case ' ':
          event.preventDefault();
          menuItems[activeIndex]?.click();
          closePopover();
          return;
      }

      if (nextIndex !== activeIndex) {
        setActiveItem(nextIndex);
      }
    });

    menu.addEventListener('mousemove', (event) => {
      const menuItem = event.target.closest('[role^="menuitem"]');
      if (menuItem && menuItems.includes(menuItem)) {
        const index = menuItems.indexOf(menuItem);
        if (index !== activeIndex) {
          setActiveItem(index);
        }
      }
    });

    menu.addEventListener('mouseleave', () => {
      setActiveItem(-1);
    });

    menu.addEventListener('click', (event) => {
      if (event.target.closest('[role^="menuitem"]')) {
        closePopover();
      }
    });

    document.addEventListener('click', (event) => {
      if (!dropdownMenuComponent.contains(event.target)) {
        closePopover();
      }
    });

    document.addEventListener('basecoat:popover', (event) => {
      if (event.detail.source !== dropdownMenuComponent) {
        closePopover(false);
      }
    });

    dropdownMenuComponent.dataset.dropdownMenuInitialized = true;
    dropdownMenuComponent.dispatchEvent(new CustomEvent('basecoat:initialized'));
  };

  if (window.basecoat) {
    window.basecoat.register('dropdown-menu', '.dropdown-menu:not([data-dropdown-menu-initialized])', initDropdownMenu);
  }
})();
