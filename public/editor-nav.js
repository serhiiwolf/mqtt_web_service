(function () {
  function createLink(href, text, title) {
    var a = document.createElement('a');
    a.href = href;
    a.textContent = text;
    a.title = title || text;
    a.className = 'button';
    return a;
  }

  function createToolbarItem(element) {
    var li = document.createElement('li');
    li.appendChild(element);
    return li;
  }

  function createLogoutLink() {
    var a = document.createElement('a');
    a.href = '#';
    a.textContent = 'Вийти';
    a.title = 'Вийти';
    a.className = 'button';

    a.addEventListener('click', function (evt) {
      evt.preventDefault();
      fetch('/logout', { method: 'POST' })
        .finally(function () {
          window.location.href = '/login';
        });
    });

    return a;
  }

  function mountNav(user, toolbar) {
    if (document.getElementById('appEditorNav')) return;

    var nav = document.createElement('ul');
    nav.id = 'appEditorNav';
    nav.style.display = 'inline-flex';
    nav.style.alignItems = 'center';
    nav.style.margin = '0';
    nav.style.padding = '0';
    nav.style.listStyle = 'none';
    nav.style.gap = '4px';

    var userLabel = document.createElement('span');
    userLabel.textContent = user && user.username ? ('Користувач: ' + user.username) : '';
    userLabel.style.fontSize = '12px';
    userLabel.style.color = '#8b949e';
    userLabel.style.margin = '0 8px 0 0';

    var userItem = document.createElement('li');
    userItem.appendChild(userLabel);

    nav.appendChild(userItem);
    nav.appendChild(createToolbarItem(createLink('/dashboard', 'Дашборд', 'Відкрити дашборд')));

    if (user && user.role === 'admin') {
      nav.appendChild(createToolbarItem(createLink('/admin', 'Адмін', 'Адмін-панель')));
      nav.appendChild(createToolbarItem(createLink('/editor', 'Редактор', 'Node-RED редактор')));
    }

    nav.appendChild(createToolbarItem(createLogoutLink()));
    toolbar.appendChild(nav);
  }

  function initWhenToolbarReady(user) {
    var retries = 0;
    var maxRetries = 20;
    var timer = setInterval(function () {
      var toolbar = document.querySelector('.red-ui-header-toolbar');
      retries += 1;
      if (toolbar) {
        clearInterval(timer);
        mountNav(user, toolbar);
      } else if (retries >= maxRetries) {
        clearInterval(timer);
      }
    }, 250);
  }

  function init() {
    fetch('/api/me')
      .then(function (r) {
        if (!r.ok) throw new Error('unauthorized');
        return r.json();
      })
      .then(function (user) {
        initWhenToolbarReady(user);
      })
      .catch(function () {
        // If session is gone, keep editor behavior unchanged.
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
