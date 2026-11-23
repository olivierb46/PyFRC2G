/* PyFRC2G web application: table filters, confirmations, firewall form, auto refresh. */
(function () {
  "use strict";

  // Filterable tables: <table data-filter> with a search box (data-search="id") and per-column inputs.
  document.querySelectorAll("table[data-filter]").forEach(function (table) {
    var inputs = table.querySelectorAll("tr.filters input");
    var search = table.dataset.search ? document.getElementById(table.dataset.search) : null;
    var counter = table.dataset.count ? document.getElementById(table.dataset.count) : null;
    var rows = Array.prototype.slice.call(table.tBodies[0].rows);
    function apply() {
      var global = search ? search.value.toLowerCase() : "";
      var values = Array.prototype.map.call(inputs, function (i) { return i.value.toLowerCase(); });
      var shown = 0;
      rows.forEach(function (row) {
        var ok = true;
        for (var i = 0; i < values.length && ok; i++) {
          if (values[i] && row.cells[i] && row.cells[i].textContent.toLowerCase().indexOf(values[i]) === -1) ok = false;
        }
        if (ok && global && row.textContent.toLowerCase().indexOf(global) === -1) ok = false;
        row.hidden = !ok;
        if (ok) shown++;
      });
      if (counter) counter.textContent = shown + " / " + rows.length;
    }
    inputs.forEach(function (i) { i.addEventListener("input", apply); });
    if (search) search.addEventListener("input", apply);
    apply();
  });

  // <input type="checkbox" data-check-all="table-id">: tick or untick the visible row checkboxes of a table.
  document.querySelectorAll("input[data-check-all]").forEach(function (box) {
    box.addEventListener("change", function () {
      var table = document.getElementById(box.dataset.checkAll);
      if (!table) return;
      table.querySelectorAll("tbody tr:not([hidden]) input[type=checkbox]").forEach(function (cb) { cb.checked = box.checked; });
    });
  });

  // Sidebar groups: collapsible, remembered. A group is open while it holds the current page; otherwise it
  // starts collapsed (so that the whole menu fits) until the user opens it.
  document.querySelectorAll(".nav-group").forEach(function (group) {
    var button = group.querySelector(".nav-title");
    var key = "pyfrc2g.nav." + group.dataset.key;
    var active = group.classList.contains("has-active");
    function set(collapsed) {
      group.classList.toggle("collapsed", collapsed);
      button.setAttribute("aria-expanded", collapsed ? "false" : "true");
    }
    var stored = null;
    try { stored = window.localStorage.getItem(key); } catch (e) { /* storage blocked */ }
    set(!active && stored !== "open");
    button.addEventListener("click", function () {
      var collapsed = !group.classList.contains("collapsed");
      set(collapsed);
      try { window.localStorage.setItem(key, collapsed ? "closed" : "open"); } catch (e) { /* ignore */ }
    });
  });

  // <form data-confirm="message">: ask before destructive actions.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  // Firewall form: show the credential fields of the selected type.
  var type = document.getElementById("fw-type");
  if (type) {
    var toggle = function () {
      document.querySelectorAll("[data-type]").forEach(function (el) {
        el.classList.toggle("hidden", el.dataset.type.split(" ").indexOf(type.value) < 0);
      });
    };
    type.addEventListener("change", toggle);
    toggle();
  }

  // <select data-autosubmit>: apply a filter as soon as it changes.
  document.querySelectorAll("select[data-autosubmit]").forEach(function (select) {
    select.addEventListener("change", function () { select.form.submit(); });
  });

  // Firewall form: show the fields of the selected mode (data-when="select-id:value").
  document.querySelectorAll("[data-when]").forEach(function (el) {
    var parts = el.dataset.when.split(":");
    var select = document.getElementById(parts[0]);
    if (!select) return;
    var update = function () { el.classList.toggle("hidden", select.value !== parts[1]); };
    select.addEventListener("change", update);
    update();
  });

  // Pages showing a running analysis refresh themselves.
  var refresh = document.body.dataset.refresh;
  if (refresh) window.setTimeout(function () { window.location.reload(); }, parseInt(refresh, 10) * 1000);
})();
