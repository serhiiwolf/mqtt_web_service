(function () {
  var nav = document.querySelector('nav');
  if (!nav || nav.dataset.uiNav) return;
  nav.dataset.uiNav = '1';
  var path = location.pathname;
  var allLinks = [
    { href: '/dashboard', label: 'Dashboard', perm: 'view:dashboard' },
    { href: '/admin/mqtt-logs', label: 'MQTT Logs', perm: 'view:mqtt_logs' },
    { href: '/admin/mqtt-devices', label: 'MQTT Devices', perm: 'manage:devices' },
    { href: '/admin', label: 'Users & Access', perm: 'view:admin' },
    { href: '/nodes/ui', label: 'Node-RED UI', perm: 'view:nodes_ui' },
    { href: '/editor', label: 'Editor', perm: 'access:editor' }
  ];
  var existing = Array.prototype.slice.call(nav.querySelectorAll('a')).map(function (a) {
    return { href: a.getAttribute('href'), label: a.textContent.trim() };
  });
  var isAuthPage = path === '/login' || path === '/register';
  nav.className = 'site-nav';
  nav.innerHTML = '';

  var brand = document.createElement('a');
  brand.href = '/dashboard';
  brand.className = 'site-brand';
  brand.innerHTML = '<span class="site-brand-mark">NR</span><span class="site-brand-copy"><strong>NODE-RED MQTT</strong><small>CONTROL PLANE // ONLINE</small></span>';
  nav.appendChild(brand);

  var linkWrap = document.createElement('div');
  linkWrap.className = 'site-links';
  var mobile = document.createElement('div');
  mobile.className = 'site-mobile-menu';

  function addLink(parent, href, text, target) {
    var a = document.createElement('a');
    a.href = href;
    a.textContent = text;
    if (target) {
      a.target = target;
      a.rel = 'noopener noreferrer';
    }
    if (path === href) a.setAttribute('aria-current', 'page');
    parent.appendChild(a);
    return a;
  }

  function renderLinks(linksList) {
    linkWrap.innerHTML = '';
    mobile.innerHTML = '';
    linksList.forEach(function (item) {
      addLink(linkWrap, item.href, item.label, item.target);
      addLink(mobile, item.href, item.label, item.target);
    });
  }

  nav.appendChild(linkWrap);

  var right = document.createElement('div');
  right.className = 'site-nav-right';
  var status = document.createElement('span');
  status.className = 'site-status';
  status.textContent = 'CONNECTING';
  right.appendChild(status);

  var user = document.createElement('span');
  user.className = 'site-user';
  right.appendChild(user);

  var login = document.createElement('a');
  login.href = '/login';
  login.className = 'site-login';
  login.textContent = 'LOGIN';
  if (!isAuthPage) right.appendChild(login);

  var logout = document.createElement('a');
  logout.href = '#';
  logout.className = 'site-logout';
  logout.textContent = 'LOGOUT';
  logout.addEventListener('click', function (e) {
    e.preventDefault();
    fetch('/logout', { method: 'POST' }).finally(function () {
      location.href = '/login';
    });
  });

  if (!isAuthPage) {
    right.appendChild(logout);
    login.style.display = 'none';
    logout.style.display = 'none';
  }
  nav.appendChild(right);

  var mobileLogin = document.createElement('a');
  mobileLogin.href = '/login';
  mobileLogin.textContent = 'LOGIN';
  mobileLogin.style.display = 'none';

  var mobileLogout = document.createElement('button');
  mobileLogout.type = 'button';
  mobileLogout.textContent = 'LOGOUT';
  mobileLogout.style.display = 'none';
  mobileLogout.addEventListener('click', function () {
    fetch('/logout', { method: 'POST' }).finally(function () {
      location.href = '/login';
    });
  });

  var toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'site-menu-toggle';
  toggle.setAttribute('aria-label', 'Open navigation');
  toggle.textContent = '☰';
  toggle.addEventListener('click', function (e) {
    e.stopPropagation();
    mobile.classList.toggle('open');
  });
  nav.appendChild(toggle);
  nav.appendChild(mobile);

  document.addEventListener('click', function () {
    mobile.classList.remove('open');
  });

  if (isAuthPage) {
    renderLinks(existing.filter(function (x) { return Boolean(x.href); }));
    status.textContent = 'AUTH GATE';
    return;
  }

  function fetchAndRenderNav() {
    return fetch('/api/me').then(function (r) {
      if (!r.ok) throw new Error('guest');
      return r.json();
    }).then(function (data) {
      status.textContent = 'BROKER ONLINE';
      user.textContent = '//' + (data.username || 'USER');
      logout.style.display = '';
      login.style.display = 'none';

      var perms = Array.isArray(data.permissions) ? data.permissions : [];
      var allowed = allLinks.filter(function (item) {
        if (!item.perm) return true;
        if (item.href === '/dashboard') {
          return perms.includes('view:dashboard') || perms.includes('view:nodes_ui') || perms.includes('view:admin');
        }
        return perms.includes(item.perm);
      });

      if (Array.isArray(data.navPages)) {
        data.navPages.forEach(function (page) {
          allowed.push({
            href: page.path,
            label: page.title,
            target: (page.path.startsWith('http://') || page.path.startsWith('https://')) ? '_blank' : null
          });
        });
      }

      renderLinks(allowed);
      mobile.appendChild(mobileLogout);
      mobileLogout.style.display = '';
      return data;
    }).catch(function () {
      status.textContent = 'PUBLIC';
      login.style.display = '';
      renderLinks([{ href: '/dashboard', label: 'Dashboard' }]);
      mobile.appendChild(mobileLogin);
      mobileLogin.style.display = '';
    });
  }

  // Pre-render minimal dashboard link while fetching permissions
  renderLinks([{ href: '/dashboard', label: 'Dashboard' }]);
  fetchAndRenderNav();

  // Expose global updater so admin actions can refresh nav bar instantly
  window.refreshSiteNav = fetchAndRenderNav;
})();
