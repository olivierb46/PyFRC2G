/* PyFRC2G popup messages ("toasts"): shows the messages of the application in a corner of the page.
 *
 * The server embeds them as JSON in <script type="application/json" id="toast-data"> (a list of [kind, text]);
 * toast(text, kind) shows one from any script. The text is only ever put in with textContent. A toast closes
 * by itself when its progress bar ends (the bar pauses while the pointer is over the toast), on a click, or
 * with its close button. No inline style or script is needed: the strict Content-Security-Policy is unchanged. */
(function () {
  "use strict";

  var MAX = 5;  // Visible at once: the oldest goes away.
  var KINDS = { ok: "success", success: "success", error: "error", warning: "warning", info: "info" };
  var box = null;

  function reduced() {
    return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function container() {
    if (box && document.body.contains(box)) return box;
    box = document.createElement("div");
    box.className = "toasts";
    box.setAttribute("aria-live", "polite");
    document.body.appendChild(box);
    return box;
  }

  function close(toast) {
    if (toast.classList.contains("leaving")) return;
    if (reduced()) { toast.remove(); return; }
    toast.classList.add("leaving");
  }

  function show(message, kind) {
    kind = KINDS[kind] || "info";
    var parent = container();
    while (parent.children.length >= MAX) parent.firstElementChild.remove();

    var toast = document.createElement("div");
    toast.className = "toast " + kind;
    toast.setAttribute("role", kind === "error" ? "alert" : "status");

    var text = document.createElement("div");
    text.className = "toast-msg";
    text.textContent = String(message);

    var button = document.createElement("button");
    button.type = "button";
    button.className = "toast-close";
    button.setAttribute("aria-label", "Close");
    button.textContent = "×";

    var bar = document.createElement("div");
    bar.className = "toast-bar";

    toast.appendChild(text);
    toast.appendChild(button);
    toast.appendChild(bar);
    parent.appendChild(toast);

    toast.addEventListener("click", function () { close(toast); });
    bar.addEventListener("animationend", function (event) { event.stopPropagation(); close(toast); });
    toast.addEventListener("animationend", function (event) {
      if (event.target === toast && toast.classList.contains("leaving")) toast.remove();
    });
    return toast;
  }

  window.toast = show;

  var data = document.getElementById("toast-data");
  if (data) {
    try {
      JSON.parse(data.textContent).forEach(function (item) { show(item[1], item[0]); });
    } catch (e) { /* malformed data: nothing to show */ }
  }
})();
