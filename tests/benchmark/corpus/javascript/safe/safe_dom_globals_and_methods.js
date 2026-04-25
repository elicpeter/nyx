// Browser DOM operations on the standard global receivers
// (`document`, `window`, `localStorage`, ...) and DOM-API methods
// (`addEventListener`, `appendChild`, `getElementById`, ...) are
// inherently client-side and never authorization-relevant.  Without
// non_sink_global_receivers / non_sink_method_names allowlists, the
// engine prefix-matched read indicator `get` against `getElementById`
// and mutation indicator `add` against `addEventListener`, firing
// `js.auth.missing_ownership_check` 200+ times on a real-repo browser
// app.  This fixture pins the suppression for both shapes.
function bindAutocomplete(inputId, options) {
  const input = document.getElementById(inputId);
  const dropdown = document.getElementById(inputId + '-dropdown');
  if (!input || !dropdown) return;

  const items = options.items || [];
  input.addEventListener('input', () => {
    dropdown.innerHTML = '';
    items.filter((it) => it.startsWith(input.value)).forEach((it) => {
      const li = document.createElement('li');
      li.textContent = it;
      dropdown.appendChild(li);
    });
  });

  input.addEventListener('blur', () => {
    setTimeout(() => dropdown.classList.remove('open'), 200);
  });

  // Browser stdlib helpers — these globals are categorically non-data-layer.
  const cached = localStorage.getItem('autocomplete:last:' + inputId);
  if (cached) {
    input.value = cached;
  }
  window.addEventListener('beforeunload', () => {
    localStorage.setItem('autocomplete:last:' + inputId, input.value);
  });
}
