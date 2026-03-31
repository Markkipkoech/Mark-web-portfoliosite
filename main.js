// main.js — Mark Kipkoech Portfolio

// ── Mobile Navigation ──────────────────────────────────────
const menuToggle = document.getElementById('mobile-menu');
const navList = document.getElementById('nav-list');

if (menuToggle && navList) {
  menuToggle.addEventListener('click', () => {
    menuToggle.classList.toggle('is-active');
    navList.classList.toggle('active');
  });

  // Close nav when a link is clicked (mobile UX)
  navList.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => {
      menuToggle.classList.remove('is-active');
      navList.classList.remove('active');
    });
  });
}

// ── Auto-highlight active nav link based on current page ───
const currentPage = window.location.pathname.split('/').pop() || 'index.html';

document.querySelectorAll('.nav-links a').forEach(link => {
  const href = link.getAttribute('href');
  if (href === currentPage) {
    link.classList.add('active');
  }
});

// ── Skill bar entrance animation ───────────────────────────
const skillBars = document.querySelectorAll('.skill-progress');

if (skillBars.length > 0) {
  const animateBars = (entries, observer) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const bar = entry.target;
        const targetWidth = bar.style.width;
        bar.style.width = '0';
        requestAnimationFrame(() => {
          setTimeout(() => { bar.style.width = targetWidth; }, 80);
        });
        observer.unobserve(bar);
      }
    });
  };

  const barObserver = new IntersectionObserver(animateBars, { threshold: 0.3 });

  skillBars.forEach(bar => {
    bar.dataset.target = bar.style.width;
    bar.style.width = '0';
    barObserver.observe(bar);
  });
}

// ── Contact form ────────────────────────────────────────────
const contactForm = document.getElementById('contact-form');

if (contactForm) {
  contactForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const btn = contactForm.querySelector('.submit-button');
    const name    = contactForm.querySelector('#name').value.trim();
    const email   = contactForm.querySelector('#email').value.trim();
    const subject = contactForm.querySelector('#subject').value.trim();
    const message = contactForm.querySelector('#message').value.trim();

    const mailtoLink = `mailto:Kipkoechmark41@gmail.com?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(`Name: ${name}\nEmail: ${email}\n\n${message}`)}`;

    btn.textContent = 'Opening mail client...';
    btn.disabled = true;
    window.location.href = mailtoLink;

    setTimeout(() => {
      btn.innerHTML = 'Send Message <i class="fas fa-paper-plane"></i>';
      btn.disabled = false;
    }, 2500);
  });
}

// ── Navbar border on scroll ─────────────────────────────────
const navbar = document.querySelector('.navbar');
if (navbar) {
  window.addEventListener('scroll', () => {
    navbar.style.borderBottomColor = window.scrollY > 40
      ? 'rgba(255,255,255,0.06)'
      : '';
  }, { passive: true });
}