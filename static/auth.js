'use strict';

// Registration wizard: reveals one step at a time and checks whether a
// username is still free. The form is fully usable without this file — every
// step is then visible in order and the browser submits normally — so each
// piece here is an enhancement rather than a requirement.

(function () {
  var wizard = document.getElementById('auth-wizard');
  if (!wizard) return;

  var steps = Array.prototype.slice.call(wizard.querySelectorAll('[data-auth-panel]'));
  var markers = Array.prototype.slice.call(document.querySelectorAll('[data-auth-step-marker]'));
  var stepField = document.getElementById('auth-step-field');
  var statusLine = document.getElementById('auth-username-status');
  var usernameInput = document.getElementById('auth-username');
  var displayInput = document.getElementById('auth-display-name');
  var passwordInput = document.getElementById('auth-password');
  var confirmInput = document.getElementById('auth-password-confirm');
  var last = steps.length;
  if (!steps.length) return;

  var current = 1;

  function show(step) {
    current = Math.min(Math.max(step, 1), last);
    steps.forEach(function (section) {
      var value = Number(section.getAttribute('data-auth-panel'));
      var active = value === current;
      section.hidden = !active;
      section.classList.toggle('is-active', active);
    });
    markers.forEach(function (marker) {
      var value = Number(marker.getAttribute('data-auth-step-marker'));
      marker.classList.toggle('is-current', value === current);
      marker.classList.toggle('is-done', value < current);
    });
    if (stepField) stepField.value = String(current);
    var active = steps[current - 1];
    if (active) {
      var focusable = active.querySelector('input:not([type="hidden"]):not([type="file"])');
      if (focusable && typeof focusable.focus === 'function') focusable.focus();
    }
  }

  // Report the first step whose required field is still empty, so pressing
  // "İleri" cannot skip past a blank display name or username.
  function stepIsComplete(step) {
    var section = steps[step - 1];
    if (!section) return true;
    var field = section.querySelector('input[required]:not([type="hidden"]):not([type="file"])');
    if (!field) return true;
    return field.value.trim().length > 0;
  }

  wizard.addEventListener('click', function (event) {
    var next = event.target.closest('[data-auth-next]');
    if (next) {
      var target = Number(next.getAttribute('data-auth-next'));
      if (!stepIsComplete(current)) {
        event.preventDefault();
        return;
      }
      event.preventDefault();
      show(target);
      return;
    }
    var back = event.target.closest('[data-auth-back]');
    if (back) {
      event.preventDefault();
      show(Number(back.getAttribute('data-auth-back')));
    }
  });

  // Passwords must match before the form is allowed to leave the page.
  wizard.addEventListener('submit', function (event) {
    if (passwordInput && confirmInput && passwordInput.value !== confirmInput.value) {
      event.preventDefault();
      show(3);
      if (confirmInput.setCustomValidity) {
        confirmInput.setCustomValidity('Parolalar eşleşmiyor.');
        confirmInput.reportValidity();
        confirmInput.setCustomValidity('');
      }
      return;
    }
    if (stepField) stepField.value = String(current);
  });

  if (confirmInput && passwordInput) {
    confirmInput.addEventListener('input', function () {
      if (confirmInput.setCustomValidity) confirmInput.setCustomValidity('');
    });
  }

  // Username availability, debounced so a fast typist issues one request.
  var lookupTimer = null;
  var lastChecked = '';
  function probeUsername() {
    if (!usernameInput || !statusLine) return;
    var value = usernameInput.value.trim();
    if (value !== lastChecked) {
      lastChecked = value;
      statusLine.textContent = '';
      statusLine.className = 'auth-hint';
    }
    if (!/^[A-Za-z0-9._-]{1,20}$/.test(value)) {
      statusLine.textContent = 'Harf, rakam, nokta, alt çizgi ve tire kullan.';
      statusLine.className = 'auth-hint';
      return;
    }
    if (lookupTimer) clearTimeout(lookupTimer);
    lookupTimer = setTimeout(function () {
      fetch('/auth/username?username=' + encodeURIComponent(value), {
        credentials: 'same-origin'
      })
        .then(function (response) {
          return response.ok ? response.json() : null;
        })
        .then(function (payload) {
          if (!payload || usernameInput.value.trim() !== value) return;
          if (payload.available) {
            statusLine.textContent = 'Bu kullanıcı adı alınmış değil.';
            statusLine.className = 'auth-ok';
          } else {
            statusLine.textContent = 'Bu kullanıcı adı zaten alınmış.';
            statusLine.className = 'auth-error';
          }
        })
        .catch(function () {
          statusLine.textContent = '';
        });
    }, 250);
  }

  if (usernameInput) {
    usernameInput.addEventListener('input', probeUsername);
    usernameInput.addEventListener('blur', probeUsername);
  }

  // Open on the step the server rejected, so a password mistype does not
  // discard the display name and username already entered.
  var initial = Number(wizard.getAttribute('data-auth-start-step') || '1');
  show(initial || 1);
  if (initial === 1 && displayInput) {
    displayInput.setAttribute('autofocus', 'autofocus');
  }
})();
