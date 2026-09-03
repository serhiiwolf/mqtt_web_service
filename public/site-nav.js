(function () {
  var nav = document.querySelector('nav');
  if (!nav || nav.dataset.uiNav) return;
  nav.dataset.uiNav = '1';
  var path = location.pathname;
  var links = [
    ['/dashboard', 'Dashboard'],
    ['/admin/mqtt-logs', 'MQTT Logs'],
    ['/admin/mqtt-devices', 'MQTT Devices'],
    ['/admin', 'Users & Access'],
    ['/nodes/ui', 'Node-RED UI'],
    ['/editor', 'Editor']
  ];
  var existing = Array.prototype.slice.call(nav.querySelectorAll('a')).map(function (a) {
    return { href: a.getAttribute('href'), text: a.textContent.trim() };
  });
  var isAuthPage = path === '/login' || path === '/register';
  nav.className = 'site-nav';
  nav.innerHTML = '';
  var brand = document.createElement('a');
  brand.href = '/dashboard'; brand.className = 'site-brand';
  brand.innerHTML = '<span class="site-brand-mark">NR</span><span class="site-brand-copy"><strong>NODE-RED MQTT</strong><small>CONTROL PLANE // ONLINE</small></span>';
  nav.appendChild(brand);
  var linkWrap = document.createElement('div'); linkWrap.className = 'site-links';
  var mobile = document.createElement('div'); mobile.className = 'site-mobile-menu';
  function addLink(parent, item) {
    var a = document.createElement('a'); a.href = item[0]; a.textContent = item[1];
    if (path === item[0]) a.setAttribute('aria-current', 'page');
    parent.appendChild(a); return a;
  }
  if (!isAuthPage) links.forEach(function (item) { addLink(linkWrap, item); });
  else existing.forEach(function (item) { if (item.href) addLink(linkWrap, [item.href, item.text]); });
  nav.appendChild(linkWrap);
  var right = document.createElement('div'); right.className = 'site-nav-right';
  var status = document.createElement('span'); status.className = 'site-status'; status.textContent = 'CONNECTING'; right.appendChild(status);
  var user = document.createElement('span'); user.className = 'site-user'; right.appendChild(user);
  var logout = document.createElement('a'); logout.href = '#'; logout.className = 'site-logout'; logout.textContent = 'LOGOUT';
  logout.addEventListener('click', function (e) { e.preventDefault(); fetch('/logout', { method: 'POST' }).finally(function () { location.href = '/login'; }); });
  if (!isAuthPage) {
    right.appendChild(logout);
    logout.style.display = 'none';
  }
  nav.appendChild(right);
  if (!isAuthPage) {
    links.forEach(function (item) { addLink(mobile, item); });
    var out = document.createElement('button'); out.type = 'button'; out.textContent = 'LOGOUT'; out.style.display = 'none';
    out.addEventListener('click', function () { fetch('/logout', { method: 'POST' }).finally(function () { location.href = '/login'; }); });
    mobile.appendChild(out);
  }
  var toggle = document.createElement('button'); toggle.type = 'button'; toggle.className = 'site-menu-toggle'; toggle.setAttribute('aria-label', 'Open navigation'); toggle.textContent = '☰';
  toggle.addEventListener('click', function (e) { e.stopPropagation(); mobile.classList.toggle('open'); });
  nav.appendChild(toggle); nav.appendChild(mobile);
  document.addEventListener('click', function () { mobile.classList.remove('open'); });
  if (isAuthPage) { status.textContent = 'AUTH GATE'; return; }
  fetch('/api/me').then(function (r) { if (!r.ok) throw new Error('guest'); return r.json(); }).then(function (data) {
    status.textContent = 'BROKER ONLINE'; user.textContent = '//' + (data.username || 'USER'); logout.style.display = ''; out.style.display = '';
  }).catch(function () { status.textContent = isAuthPage ? 'AUTH GATE' : 'PUBLIC'; });
})();
