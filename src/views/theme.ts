export const THEME_CSS = `
:root[data-theme="light"] {
  --bg: #ffffff; --bg-soft: #f8fafc; --surface: #ffffff;
  --border: #e2e8f0; --text: #0f172a; --text-muted: #64748b;
  --primary: #0f172a; --accent: #2563eb;
  --success: #16a34a; --danger: #dc2626; --warning: #d97706;
  --warning-bg: #fffbeb;
}
:root[data-theme="dark"] {
  --bg: #0b1220; --bg-soft: #111827; --surface: #1e293b;
  --border: #334155; --text: #f1f5f9; --text-muted: #94a3b8;
  --primary: #f1f5f9; --accent: #38bdf8;
  --success: #4ade80; --danger: #f87171; --warning: #fbbf24;
  --warning-bg: #1f1306;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg-soft); color: var(--text); min-height: 100vh;
  padding: 16px;
}
.container { max-width: 920px; margin: 0 auto; }
header.topbar {
  display: flex; justify-content: space-between; align-items: center;
  padding: 12px 16px; background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; margin-bottom: 16px;
}
header.topbar .actions { display: flex; gap: 8px; align-items: center; }
.btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 14px;
  border: 1px solid var(--border); border-radius: 6px; background: var(--surface);
  color: var(--text); cursor: pointer; font-size: 14px; }
.btn:hover { background: var(--bg-soft); }
.btn.primary { background: var(--primary); color: var(--bg); border-color: var(--primary); }
.btn.accent { background: var(--accent); color: var(--bg); border-color: var(--accent); }
.btn.danger { color: var(--danger); border-color: var(--danger); }
.btn.small { padding: 4px 10px; font-size: 12px; }
.card { background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px; margin-bottom: 16px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px; margin-bottom: 16px; }
.stat { background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 14px; }
.stat .label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; }
.stat .value { font-size: 20px; font-weight: 600; margin-top: 4px; }
input, select, textarea {
  width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 6px;
  background: var(--bg); color: var(--text); font-size: 14px; font-family: inherit;
}
input:focus, select:focus, textarea:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
label { display: block; font-size: 13px; color: var(--text-muted); margin-bottom: 6px; }
.form-row { display: flex; gap: 12px; flex-wrap: wrap; }
.form-row > * { flex: 1 1 200px; }
.banner { padding: 12px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
.banner.success { background: rgba(22, 163, 74, 0.08); color: var(--success);
  border-left: 3px solid var(--success); }
.banner.error { background: rgba(220, 38, 38, 0.08); color: var(--danger);
  border-left: 3px solid var(--danger); }
.banner.info { background: rgba(37, 99, 235, 0.08); color: var(--accent);
  border-left: 3px solid var(--accent); }
code { background: var(--bg-soft); padding: 1px 5px; border-radius: 3px; font-size: 0.9em; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.repo-card { background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px; margin-bottom: 12px; }
.repo-card .repo-header { display: flex; justify-content: space-between; align-items: flex-start; }
.repo-card .branch-tag { background: var(--bg-soft); color: var(--text-muted);
  padding: 2px 8px; border-radius: 6px; font-size: 12px; font-weight: 500; margin-left: 8px; }
.repo-card .fork-section { border-top: 1px solid var(--border); margin: 12px -16px -16px;
  padding: 12px 16px; background: var(--bg-soft); border-radius: 0 0 10px 10px; }
.repo-card .fork-section.warning { background: var(--warning-bg); }
.muted { color: var(--text-muted); font-size: 13px; }
footer.footer { margin-top: 24px; padding: 12px 16px; font-size: 12px;
  color: var(--text-muted); text-align: center; }
`

export const THEME_INIT_SCRIPT = `
(function() {
  function read(name) {
    var m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
    return m ? decodeURIComponent(m[1]) : null;
  }
  var saved = read('theme');
  var pref = saved || (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', pref);
})();
`

export const THEME_TOGGLE_SCRIPT = `
function toggleTheme() {
  var cur = document.documentElement.getAttribute('data-theme');
  var next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  document.cookie = 'theme=' + next + '; path=/; max-age=' + (60*60*24*365) + '; SameSite=Strict';
}
`
