// main.js — Mark Kipkoech Portfolio

// ── Mobile Navigation ──────────────────────────────────────
const menuToggle = document.getElementById('mobile-menu');
const navList = document.getElementById('nav-list');

if (menuToggle && navList) {
  const setMenuOpen = isOpen => {
    menuToggle.classList.toggle('is-active', isOpen);
    navList.classList.toggle('active', isOpen);
    menuToggle.setAttribute('aria-expanded', String(isOpen));
  };

  menuToggle.addEventListener('click', () => {
    setMenuOpen(!navList.classList.contains('active'));
  });

  navList.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => {
      setMenuOpen(false);
    });
  });

  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && navList.classList.contains('active')) {
      setMenuOpen(false);
      menuToggle.focus();
    }
  });
}

// ── Auto-highlight active nav link based on current page ───
const currentPage = window.location.pathname.split('/').pop() || 'index.html';

document.querySelectorAll('.nav-links a').forEach(link => {
  const isCurrentPage = link.getAttribute('href') === currentPage;
  link.classList.toggle('active', isCurrentPage);

  if (isCurrentPage) {
    link.setAttribute('aria-current', 'page');
  } else {
    link.removeAttribute('aria-current');
  }
});

// ── Navbar border on scroll ─────────────────────────────────
const navbar = document.querySelector('.navbar');
if (navbar) {
  window.addEventListener('scroll', () => {
    navbar.style.borderBottomColor = window.scrollY > 40
      ? 'rgba(255,255,255,0.06)'
      : '';
  }, { passive: true });
}