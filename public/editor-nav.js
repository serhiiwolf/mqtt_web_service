(function () {
  function addStyles() {
    if (document.getElementById('mqttEditorNavStyles')) return;
    var style = document.createElement('style');
    style.id = 'mqttEditorNavStyles';
    style.textContent = '.mqtt-editor-nav{display:flex;align-items:center;gap:2px;margin-left:10px;font:10px "JetBrains Mono",monospace}.mqtt-editor-nav .nav-links{display:flex;align-items:center;gap:2px}.mqtt-editor-nav a{padding:7px 8px;color:#8190a6;text-decoration:none;border-bottom:2px solid transparent}.mqtt-editor-nav a:hover{color:#e6edf7;border-bottom-color:#ff7a18}.mqtt-editor-nav .state{margin-left:8px;color:#38d996;font-size:9px}.mqtt-editor-nav .menu-btn{display:none;background:transparent;border:1px solid #354153;color:#e6edf7;padding:5px 8px}@media(max-width:900px){.mqtt-editor-nav .nav-links{display:none;position:absolute;right:8px;top:38px;padding:5px;background:#111823;border:1px solid #354153}.mqtt-editor-nav .nav-links.open{display:grid}.mqtt-editor-nav .nav-links a{border:0;white-space:nowrap}.mqtt-editor-nav .menu-btn{display:block}}';
    document.head.appendChild(style);
  }
  function link(href, text, current) {
    var a = document.createElement('a');
    a.href = href; a.textContent = text; a.className = 'nav-link';
    if (href.startsWith('http://') || href.startsWith('https://')) {
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
    }
    if (location.pathname === href) a.style.color = '#e6edf7';
    if (current) a.setAttribute('aria-current', 'page');
    return a;
  }
  function mount(user, toolbar) {
    if (document.getElementById('appEditorNav')) return;
    addStyles();
    var wrap = document.createElement('div');
    wrap.id = 'appEditorNav'; wrap.className = 'mqtt-editor-nav'; wrap.style.position = 'relative';
    var links = [
      ['/dashboard', 'DASHBOARD'],
      ['/admin/mqtt-logs', 'MQTT LOGS'],
      ['/admin/mqtt-devices', 'MQTT DEVICES'],
      ['/admin', 'USERS & ACCESS'],
      ['/nodes/ui', 'NODE-RED UI']
    ];
    var perms = user && user.permissions || [];
    var allowed = links.filter(function (item) {
      return item[0] === '/dashboard' || (item[0] === '/admin/mqtt-logs' && perms.indexOf('view:mqtt_logs') !== -1) ||
        (item[0] === '/admin/mqtt-devices' && perms.indexOf('manage:devices') !== -1) ||
        (item[0] === '/admin' && perms.indexOf('view:admin') !== -1) ||
        (item[0] === '/nodes/ui' && perms.indexOf('view:nodes_ui') !== -1);
    });

    if (Array.isArray(user.navPages)) {
      user.navPages.forEach(function (page) {
        allowed.push([page.path, page.title.toUpperCase()]);
      });
    }

    var navLinks = document.createElement('div'); navLinks.className = 'nav-links';
    allowed.forEach(function (item) { navLinks.appendChild(link(item[0], item[1])); });
    var state = document.createElement('span'); state.className = 'state'; state.textContent = '● SESSION ' + (user.username || 'OK');
    var button = document.createElement('button'); button.type = 'button'; button.className = 'menu-btn'; button.textContent = '☰';
    button.addEventListener('click', function (event) { event.stopPropagation(); navLinks.classList.toggle('open'); });
    wrap.appendChild(navLinks); wrap.appendChild(state); wrap.appendChild(button); toolbar.appendChild(wrap);
    document.addEventListener('click', function () { navLinks.classList.remove('open'); });
  }
  function init() {
    fetch('/api/me').then(function (response) { if (!response.ok) throw new Error('auth'); return response.json(); }).then(function (user) {
      var attempts = 0;
      var timer = setInterval(function () {
        var toolbar = document.querySelector('.red-ui-header-toolbar');
        if (toolbar) { clearInterval(timer); mount(user, toolbar); }
        if (++attempts > 60) clearInterval(timer);
      }, 250);
    }).catch(function () {});
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
