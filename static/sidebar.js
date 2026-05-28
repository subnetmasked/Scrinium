(function () {
  const sidebar = document.querySelector(".sidebar");
  if (!sidebar) return;

  const input = document.getElementById("sidebar-filter");
  const emptyState = document.getElementById("sidebar-empty");
  if (!input || !emptyState) return;

  const items = Array.from(sidebar.querySelectorAll("li"));
  const detailsNodes = Array.from(sidebar.querySelectorAll("details"));
  const navSections = Array.from(
    sidebar.querySelectorAll("details.nav-section[data-section]")
  );
  const preSearchOpen = new Map();
  let isFiltering = false;

  function storageKey(sectionId) {
    return `scrinium.sidebar.${sectionId}`;
  }

  function leafAnchorForItem(item) {
    return (
      item.querySelector(":scope > a") ||
      item.querySelector(":scope > details > summary > .folder-name") ||
      item.querySelector(":scope > details > summary > .entry-name")
    );
  }

  function clearHighlight(anchor) {
    const original = anchor.dataset.originalLabel;
    if (original !== undefined) {
      anchor.textContent = original;
    }
  }

  function setHighlight(anchor, query) {
    const original =
      anchor.dataset.originalLabel !== undefined
        ? anchor.dataset.originalLabel
        : anchor.textContent;
    anchor.dataset.originalLabel = original;
    if (!query) {
      anchor.textContent = original;
      return;
    }
    const lower = original.toLowerCase();
    const idx = lower.indexOf(query);
    if (idx < 0) {
      anchor.textContent = original;
      return;
    }
    const before = original.slice(0, idx);
    const match = original.slice(idx, idx + query.length);
    const after = original.slice(idx + query.length);
    anchor.textContent = "";
    if (before) anchor.appendChild(document.createTextNode(before));
    const mark = document.createElement("mark");
    mark.textContent = match;
    anchor.appendChild(mark);
    if (after) anchor.appendChild(document.createTextNode(after));
  }

  function saveSectionState(section) {
    const sectionId = section.dataset.section;
    if (!sectionId) return;
    try {
      localStorage.setItem(storageKey(sectionId), section.open ? "open" : "closed");
    } catch (_err) {
      // Ignore localStorage failures (private mode, quota, etc.).
    }
  }

  function loadSectionState(section) {
    const sectionId = section.dataset.section;
    if (!sectionId) return;
    try {
      const saved = localStorage.getItem(storageKey(sectionId));
      if (saved === "open") section.open = true;
      if (saved === "closed") section.open = false;
    } catch (_err) {
      // Ignore localStorage failures and keep server-rendered default.
    }
  }

  navSections.forEach((section) => {
    loadSectionState(section);
    section.addEventListener("toggle", () => {
      if (isFiltering) return;
      saveSectionState(section);
    });
  });

  function restoreAfterSearch() {
    items.forEach((item) => {
      item.hidden = false;
      const anchor = leafAnchorForItem(item);
      if (anchor) clearHighlight(anchor);
    });
    detailsNodes.forEach((node) => {
      if (preSearchOpen.has(node)) {
        node.open = Boolean(preSearchOpen.get(node));
      }
    });
    navSections.forEach((section) => {
      section.hidden = false;
    });
    emptyState.hidden = true;
    preSearchOpen.clear();
    isFiltering = false;
  }

  function runFilter() {
    const query = input.value.trim().toLowerCase();
    if (!query) {
      restoreAfterSearch();
      return;
    }

    if (!isFiltering) {
      detailsNodes.forEach((node) => {
        preSearchOpen.set(node, node.open);
      });
    }
    isFiltering = true;

    let visibleItemCount = 0;
    items.forEach((item) => {
      const anchor = leafAnchorForItem(item);
      if (!anchor) {
        item.hidden = true;
        return;
      }
      const text =
        anchor.dataset.originalLabel !== undefined
          ? anchor.dataset.originalLabel
          : anchor.textContent;
      const matches = text.toLowerCase().includes(query);
      item.hidden = !matches;
      if (matches) {
        visibleItemCount += 1;
        setHighlight(anchor, query);
        let parent = item.parentElement;
        while (parent && parent !== sidebar) {
          if (parent.tagName === "DETAILS") {
            parent.open = true;
          }
          parent = parent.parentElement;
        }
      } else {
        clearHighlight(anchor);
      }
    });

    navSections.forEach((section) => {
      const hasVisibleItems = Boolean(section.querySelector("li:not([hidden])"));
      section.hidden = !hasVisibleItems;
    });
    emptyState.hidden = visibleItemCount > 0;
  }

  input.addEventListener("input", runFilter);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && input.value) {
      input.value = "";
      runFilter();
      event.preventDefault();
    }
  });
})();
