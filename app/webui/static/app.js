/* Orchestrator ACME Cert Manager — no build step, no dependencies.
 *
 * 1. Theme toggle, persisted in localStorage (dark is the default).
 * 2. Live refresh: any element with data-live="<url>" has its innerHTML
 *    replaced by the server-rendered fragment at that URL. The interval is
 *    short while a run is in progress (data-busy="1") and relaxed otherwise.
 *    Open <details data-key> elements stay open across swaps; the page is
 *    reloaded if the session expired (the fetch lands on /login).
 */
(function () {
  'use strict';

  // ---- theme -------------------------------------------------------------
  var root = document.documentElement;
  var toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('oacm-theme', next); } catch (e) {}
    });
  }

  // ---- confirmations -----------------------------------------------------
  document.addEventListener('submit', function (ev) {
    var f = ev.target;
    if (f && f.hasAttribute('data-confirm') && !window.confirm(f.getAttribute('data-confirm'))) {
      ev.preventDefault();
    }
  });

  // ---- driver selector on the target form --------------------------------
  var driverSel = document.getElementById('driver');
  if (driverSel) {
    var sync = function () {
      var chosen = driverSel.value;
      document.querySelectorAll('.driver-section').forEach(function (sec) {
        var on = sec.getAttribute('data-driver') === chosen;
        if (on) sec.removeAttribute('hidden'); else sec.setAttribute('hidden', '');
        sec.querySelectorAll('input, select, textarea').forEach(function (el) { el.disabled = !on; });
      });
    };
    driverSel.addEventListener('change', sync);
    sync();
  }

  // ---- live refresh ------------------------------------------------------
  var BUSY_MS = 8000, IDLE_MS = 45000;
  var live = document.querySelector('[data-live]');
  if (!live) return;

  var timer = null, inflight = false;

  function openKeys(scope) {
    var keys = {};
    scope.querySelectorAll('details[data-key][open]').forEach(function (d) { keys[d.getAttribute('data-key')] = 1; });
    return keys;
  }
  function restoreKeys(scope, keys) {
    scope.querySelectorAll('details[data-key]').forEach(function (d) {
      if (keys[d.getAttribute('data-key')]) d.setAttribute('open', '');
    });
  }
  function interval() { return live.getAttribute('data-busy') === '1' ? BUSY_MS : IDLE_MS; }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(refresh, interval());
  }

  function focusInside() {
    var a = document.activeElement;
    return a && a !== document.body && live.contains(a);
  }

  function refresh() {
    // Never yank the keyboard focus out from under someone who is on a button or reading a block.
    if (document.hidden || inflight || focusInside()) { schedule(); return; }
    inflight = true;
    var url = live.getAttribute('data-live');
    fetch(url, { credentials: 'same-origin', headers: { 'X-Requested-With': 'live' } })
      .then(function (res) {
        if (res.redirected && /\/login/.test(res.url)) { window.location.reload(); return null; }
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.text();
      })
      .then(function (html) {
        if (html === null) return;
        var keys = openKeys(live);
        var tmp = document.createElement('div');
        tmp.innerHTML = html;
        var next = tmp.firstElementChild;
        if (!next) return;
        live.setAttribute('data-busy', next.getAttribute('data-busy') || '0');
        live.innerHTML = next.innerHTML;
        restoreKeys(live, keys);
        var stamp = document.getElementById('live-updated');
        if (stamp) { stamp.textContent = 'updated ' + new Date().toLocaleTimeString(); stamp.classList.remove('stale'); }
      })
      .catch(function () {
        var stamp = document.getElementById('live-updated');
        if (stamp) { stamp.textContent = 'refresh failed — retrying'; stamp.classList.add('stale'); }
      })
      .then(function () { inflight = false; schedule(); });
  }

  document.addEventListener('visibilitychange', function () { if (!document.hidden) refresh(); });
  schedule();
})();
