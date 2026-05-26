(function () {
  const ta = document.getElementById("editor-body");
  const preview = document.getElementById("preview");
  const toggle = document.getElementById("toggle-preview");
  const form = document.getElementById("edit-form");
  const pickBtn = document.getElementById("pick-image");
  const fileInput = document.getElementById("image-input");
  const fmBtn = document.getElementById("insert-fm");
  const fmTpl = document.getElementById("fm-template-data");
  if (!ta) return;

  const FRONTMATTER_RE = /^---\r?\n[\s\S]*?\r?\n---\r?\n?/;

  function syncFmButton() {
    if (!fmBtn) return;
    fmBtn.hidden = FRONTMATTER_RE.test(ta.value);
  }

  function insertFrontmatter() {
    if (!fmTpl) return;
    if (FRONTMATTER_RE.test(ta.value)) return;
    const tplText = (fmTpl.content?.textContent || fmTpl.innerHTML || "").trim();
    if (!tplText) return;
    const sep = ta.value.startsWith("\n") ? "" : "\n";
    ta.value = tplText + "\n" + sep + ta.value;
    ta.setSelectionRange(0, 0);
    ta.focus();
    ta.scrollTop = 0;
    syncFmButton();
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  }

  const docRel = window.SCRINIUM_DOC_REL || "";
  const csrf = () =>
    document.querySelector('meta[name="csrf-token"]')?.content || "";

  function insertAtCaret(text) {
    const start = ta.selectionStart;
    const end = ta.selectionEnd;
    const before = ta.value.slice(0, start);
    const after = ta.value.slice(end);
    ta.value = before + text + after;
    const pos = start + text.length;
    ta.selectionStart = ta.selectionEnd = pos;
    ta.focus();
    return { start, placeholder: text, length: text.length };
  }

  function replaceRange(start, oldLen, replacement) {
    const before = ta.value.slice(0, start);
    const after = ta.value.slice(start + oldLen);
    ta.value = before + replacement + after;
    const pos = start + replacement.length;
    ta.selectionStart = ta.selectionEnd = pos;
    ta.focus();
  }

  async function uploadBlob(blob, filename, pasted) {
    const fd = new FormData();
    fd.append("file", blob, filename || "image.png");
    if (pasted) fd.append("pasted", "1");
    const url = `/api/upload?for=${encodeURIComponent(docRel)}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf() },
      body: fd,
    });
    if (!res.ok) {
      const msg = await res.text();
      throw new Error(msg || `Upload failed (${res.status})`);
    }
    return res.json();
  }

  async function handleFiles(files, pasted) {
    for (const file of files) {
      if (!file.type.startsWith("image/")) continue;
      const placeholder = "![uploading…](#)";
      const pos = insertAtCaret(placeholder + "\n");
      try {
        const data = await uploadBlob(file, file.name, pasted);
        replaceRange(pos.start, pos.length, data.markdown + "\n");
      } catch (err) {
        replaceRange(pos.start, pos.length, `<!-- upload failed: ${err.message} -->\n`);
      }
    }
  }

  ta.addEventListener("keydown", (e) => {
    if (e.key === "Tab" && !e.shiftKey) {
      e.preventDefault();
      const start = ta.selectionStart;
      const end = ta.selectionEnd;
      ta.value = ta.value.slice(0, start) + "  " + ta.value.slice(end);
      ta.selectionStart = ta.selectionEnd = start + 2;
    }
    if ((e.ctrlKey || e.metaKey) && e.key === "s") {
      e.preventDefault();
      form.submit();
    }
  });

  ta.addEventListener("paste", (e) => {
    const items = e.clipboardData?.items;
    if (!items) return;
    const images = [];
    for (const item of items) {
      if (item.type.startsWith("image/")) {
        const blob = item.getAsFile();
        if (blob) images.push(blob);
      }
    }
    if (!images.length) return;
    e.preventDefault();
    handleFiles(images, true);
  });

  ta.addEventListener("dragover", (e) => {
    if (e.dataTransfer?.types?.includes("Files")) {
      e.preventDefault();
    }
  });

  ta.addEventListener("drop", (e) => {
    const files = e.dataTransfer?.files;
    if (!files?.length) return;
    e.preventDefault();
    handleFiles(files, false);
  });

  fmBtn?.addEventListener("click", insertFrontmatter);
  ta.addEventListener("input", syncFmButton);

  pickBtn?.addEventListener("click", () => fileInput?.click());
  fileInput?.addEventListener("change", () => {
    if (fileInput.files?.length) {
      handleFiles(fileInput.files, false);
      fileInput.value = "";
    }
  });

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
        const previewUrl = docRel
          ? `/api/preview?for=${encodeURIComponent(docRel)}`
          : "/api/preview";
        const res = await fetch(previewUrl, {
          method: "POST",
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "X-CSRF-Token": csrf(),
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
