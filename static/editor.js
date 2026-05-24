(function () {
  const ta = document.getElementById("editor-body");
  const preview = document.getElementById("preview");
  const toggle = document.getElementById("toggle-preview");
  const form = document.getElementById("edit-form");
  if (!ta) return;

  // Tab inserts two spaces instead of changing focus.
  ta.addEventListener("keydown", (e) => {
    if (e.key === "Tab" && !e.shiftKey) {
      e.preventDefault();
      const start = ta.selectionStart;
      const end = ta.selectionEnd;
      ta.value = ta.value.slice(0, start) + "  " + ta.value.slice(end);
      ta.selectionStart = ta.selectionEnd = start + 2;
    }
    // Ctrl+S / Cmd+S submits
    if ((e.ctrlKey || e.metaKey) && e.key === "s") {
      e.preventDefault();
      form.submit();
    }
  });

  // Preview toggle (lazy fetch).
  let previewing = false;
  let lastValue = null;
  toggle?.addEventListener("click", async () => {
    previewing = !previewing;
    if (!previewing) {
      preview.classList.add("hidden");
      ta.classList.remove("hidden");
      toggle.textContent = "Preview";
      return;
    }
    toggle.textContent = "Edit";
    ta.classList.add("hidden");
    preview.classList.remove("hidden");
    if (ta.value !== lastValue) {
      preview.textContent = "Rendering…";
      try {
        const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
        const res = await fetch("/api/preview", {
          method: "POST",
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "X-CSRF-Token": csrf,
          },
          body: ta.value,
        });
        preview.innerHTML = await res.text();
        lastValue = ta.value;
      } catch (err) {
        preview.textContent = "Preview failed: " + err;
      }
    }
  });
})();
