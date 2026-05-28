(function () {
  const ta = document.getElementById("editor-body");
  const preview = document.getElementById("preview");
  const toggle = document.getElementById("toggle-preview");
  const form = document.getElementById("edit-form");
  const pickBtn = document.getElementById("pick-image");
  const fileInput = document.getElementById("image-input");
  const fmBtn = document.getElementById("insert-fm");
  const fmTpl = document.getElementById("fm-template-data");
  const wikiBtn = document.getElementById("wrap-wikilink");
  const attachBtn = document.getElementById("pick-attachment");
  const attachInput = document.getElementById("attachment-input");
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

  function wrapWikilinkAtSelection() {
    const start = ta.selectionStart;
    const end = ta.selectionEnd;
    const selected = ta.value.slice(start, end);

    // Toggle: if the selection is already surrounded by [[ ]], strip it.
    const before2 = ta.value.slice(Math.max(0, start - 2), start);
    const after2 = ta.value.slice(end, end + 2);
    if (before2 === "[[" && after2 === "]]") {
      ta.value =
        ta.value.slice(0, start - 2) + selected + ta.value.slice(end + 2);
      ta.selectionStart = start - 2;
      ta.selectionEnd = end - 2;
      ta.focus();
      ta.dispatchEvent(new Event("input", { bubbles: true }));
      return;
    }

    if (!selected) {
      const inserted = "[[]]";
      ta.value = ta.value.slice(0, start) + inserted + ta.value.slice(end);
      ta.selectionStart = ta.selectionEnd = start + 2;
      ta.focus();
      ta.dispatchEvent(new Event("input", { bubbles: true }));
      return;
    }

    // Wikilinks are single-line tokens; collapse internal whitespace so a
    // selection spanning a soft-wrapped line still yields a valid target.
    const flat = selected.replace(/\s*\n\s*/g, " ").trim();
    if (!flat) {
      ta.focus();
      return;
    }
    const wrapped = `[[${flat}]]`;
    ta.value = ta.value.slice(0, start) + wrapped + ta.value.slice(end);
    ta.selectionStart = start + 2;
    ta.selectionEnd = start + 2 + flat.length;
    ta.focus();
    ta.dispatchEvent(new Event("input", { bubbles: true }));
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
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      wrapWikilinkAtSelection();
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
  wikiBtn?.addEventListener("click", wrapWikilinkAtSelection);
  ta.addEventListener("input", syncFmButton);

  pickBtn?.addEventListener("click", () => fileInput?.click());
  fileInput?.addEventListener("change", () => {
    if (fileInput.files?.length) {
      handleFiles(fileInput.files, false);
      fileInput.value = "";
    }
  });

  async function uploadAttachment(file) {
    const fd = new FormData();
    fd.append("file", file, file.name || "attachment.bin");
    const res = await fetch(`/api/attach?for=${encodeURIComponent(docRel)}`, {
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

  attachBtn?.addEventListener("click", () => attachInput?.click());
  attachInput?.addEventListener("change", async () => {
    if (!attachInput.files?.length) return;
    for (const file of attachInput.files) {
      try {
        await uploadAttachment(file);
      } catch (err) {
        window.alert(`Attachment upload failed: ${err.message}`);
      }
    }
    attachInput.value = "";
    window.alert("Attachment upload complete. Open the document view to see files.");
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
