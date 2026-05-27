(function () {
  "use strict";

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        document.body.removeChild(ta);
      }
    });
  }

  function languageLabel(codeEl) {
    if (!codeEl || !codeEl.classList) return "";
    for (var i = 0; i < codeEl.classList.length; i++) {
      var cls = codeEl.classList[i];
      if (cls.indexOf("language-") === 0) {
        return cls.slice(9);
      }
    }
    return "";
  }

  function enhanceBlock(pre) {
    if (!pre || pre.closest(".code-block")) return;
    var code = pre.querySelector("code");
    if (!code) return;

    var wrap = document.createElement("div");
    wrap.className = "code-block";
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(pre);

    var toolbar = document.createElement("div");
    toolbar.className = "code-toolbar";
    var lang = languageLabel(code);
    if (lang) {
      var langEl = document.createElement("span");
      langEl.className = "code-lang";
      langEl.textContent = lang;
      toolbar.appendChild(langEl);
    }

    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-btn";
    btn.setAttribute("aria-label", "Copy code");
    btn.textContent = "Copy";
    btn.addEventListener("click", function () {
      copyText(code.textContent || "")
        .then(function () {
          btn.textContent = "Copied";
          btn.classList.add("copied");
          window.setTimeout(function () {
            btn.textContent = "Copy";
            btn.classList.remove("copied");
          }, 1500);
        })
        .catch(function () {
          btn.textContent = "Failed";
          window.setTimeout(function () {
            btn.textContent = "Copy";
          }, 1500);
        });
    });
    toolbar.appendChild(btn);
    wrap.insertBefore(toolbar, pre);
  }

  function init() {
    var root = document.querySelector("article.doc-body");
    if (!root) return;
    root.querySelectorAll("div.codehilite > pre, pre:not(.codehilite pre)").forEach(enhanceBlock);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
