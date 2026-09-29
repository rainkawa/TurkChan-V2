// data-active-theme and theme attributes and the blocking stylesheet are rendered by the server.
// Only enable progressive enhancement here; never replace that stylesheet.
//
// Appearance is read from a cookie rather than rendered by the server, because
// the layout is handed a theme name and not the cookie jar it arrived in.
// Reading it here is the one place that happens early enough for the choice to
// land before the first paint, which is what stops a reader who prefers light
// from being flashed a dark page on every navigation.
(function () {
  var COOKIE = 'rustchan_color_mode';
  var MODES = ['dark', 'light', 'system'];
  var DEFAULT_MODE = 'dark';

  function stored() {
    var match = document.cookie.match(
      new RegExp('(?:^|; )' + COOKIE + '=([^;]*)')
    );
    return match ? decodeURIComponent(match[1]) : '';
  }

  function normalize(mode) {
    return MODES.indexOf(mode) === -1 ? DEFAULT_MODE : mode;
  }

  function pressedFor(mode) {
    var buttons = document.querySelectorAll('.color-mode-btn');
    for (var i = 0; i < buttons.length; i += 1) {
      var active = buttons[i].getAttribute('data-color-mode-value') === mode;
      buttons[i].setAttribute('aria-pressed', active ? 'true' : 'false');
    }
  }

  function apply(mode) {
    var resolved = normalize(mode);
    document.documentElement.setAttribute('data-color-mode', resolved);
    return resolved;
  }

  // Shared with the header switch so the cookie is named and validated once.
  window.chanColorMode = {
    cookie: COOKIE,
    modes: MODES,
    defaultMode: DEFAULT_MODE,
    read: function () {
      return normalize(stored());
    },
    apply: apply,
    save: function (mode) {
      var resolved = apply(mode);
      var oneYear = 60 * 60 * 24 * 365;
      document.cookie =
        COOKIE +
        '=' +
        encodeURIComponent(resolved) +
        '; path=/; max-age=' +
        oneYear +
        '; SameSite=Lax';
      pressedFor(resolved);
      return resolved;
    }
  };

  apply(stored());
  document.documentElement.classList.remove('no-js');
  document.documentElement.classList.add('js');

  // The switch is rendered by the server without knowing which button is
  // current, because the answer lives in the cookie this script just read.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      pressedFor(window.chanColorMode.read());
    });
  } else {
    pressedFor(window.chanColorMode.read());
  }
})();
