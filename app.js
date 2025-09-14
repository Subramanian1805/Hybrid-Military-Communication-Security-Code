// DOM Content Loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize all functionality
    initSmoothScrolling();
    initCounterAnimation();
    initNavHighlight();
    initScrollAnimations();
    initGitHubLinks();
});

// Fix GitHub links functionality
function initGitHubLinks() {
    const githubLinks = document.querySelectorAll('a[href*="github.com"]');
    
    githubLinks.forEach(link => {
        // Ensure proper target and rel attributes
        link.setAttribute('target', '_blank');
        link.setAttribute('rel', 'noopener noreferrer');
        
        // Add click event listener to ensure it works
        link.addEventListener('click', function(e) {
            // Don't prevent default, but ensure the link works
            console.log('Opening GitHub link:', this.href);
            
            // Fallback method if normal click doesn't work
            if (!this.href || this.href === '#') {
                e.preventDefault();
                window.open('https://github.com/Subramanian1805/Hybrid-Military-Communication-Security-Code/tree/main', '_blank');
            }
        });
    });
}

// Enhanced smooth scrolling for navigation links
function initSmoothScrolling() {
    const navLinks = document.querySelectorAll('.nav__link');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            const href = this.getAttribute('href');
            
            // Only prevent default for internal links (starting with #)
            if (href && href.startsWith('#')) {
                e.preventDefault();
                
                const targetId = href;
                let targetSection = document.querySelector(targetId);
                
                // Handle special cases for section mapping
                if (!targetSection) {
                    switch(targetId) {
                        case '#home':
                            targetSection = document.querySelector('.hero');
                            break;
                        case '#features':
                            targetSection = document.querySelector('.features');
                            break;
                        case '#technology':
                            targetSection = document.querySelector('.technology');
                            break;
                        case '#team':
                            targetSection = document.querySelector('.team');
                            break;
                        case '#contact':
                            targetSection = document.querySelector('.contact');
                            break;
                    }
                }
                
                if (targetSection) {
                    const headerHeight = document.querySelector('.header').offsetHeight;
                    const targetPosition = targetSection.offsetTop - headerHeight;
                    
                    window.scrollTo({
                        top: targetPosition,
                        behavior: 'smooth'
                    });
                    
                    // Update URL hash without triggering scroll
                    history.pushState(null, null, targetId);
                } else {
                    console.warn('Target section not found:', targetId);
                }
            }
        });
    });

    // Handle direct hash navigation (when user enters URL with hash)
    if (window.location.hash) {
        setTimeout(() => {
            const targetSection = document.querySelector(window.location.hash);
            if (targetSection) {
                const headerHeight = document.querySelector('.header').offsetHeight;
                const targetPosition = targetSection.offsetTop - headerHeight;
                
                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
            }
        }, 100);
    }
}

// Animated counters for statistics
function initCounterAnimation() {
    const counters = document.querySelectorAll('.stat__value');
    let hasAnimated = false;

    const animateCounters = () => {
        if (hasAnimated) return;
        
        const heroSection = document.querySelector('.hero');
        const heroRect = heroSection.getBoundingClientRect();
        
        // Check if hero section is in view
        if (heroRect.top <= window.innerHeight && heroRect.bottom >= 0) {
            hasAnimated = true;
            
            counters.forEach(counter => {
                const target = parseFloat(counter.getAttribute('data-target'));
                const increment = target / 50; // Slower animation
                let current = 0;
                
                const updateCounter = () => {
                    if (current < target) {
                        current += increment;
                        if (current > target) current = target;
                        
                        // Format the number based on the target
                        if (target === 99.9) {
                            counter.textContent = current.toFixed(1);
                        } else if (target === 1) {
                            counter.textContent = current < 1 ? '<1' : '1';
                        } else {
                            counter.textContent = Math.floor(current);
                        }
                        
                        setTimeout(updateCounter, 50);
                    } else {
                        // Set final value
                        if (target === 99.9) {
                            counter.textContent = '99.9';
                        } else if (target === 1) {
                            counter.textContent = '<1';
                        } else {
                            counter.textContent = target.toString();
                        }
                    }
                };
                
                // Start animation with a slight delay for each counter
                setTimeout(() => {
                    updateCounter();
                }, Array.from(counters).indexOf(counter) * 200);
            });
        }
    };

    // Check on scroll
    window.addEventListener('scroll', animateCounters);
    // Check on load
    setTimeout(animateCounters, 500);
}

// Highlight active navigation item
function initNavHighlight() {
    const sections = document.querySelectorAll('section[id], .hero');
    const navLinks = document.querySelectorAll('.nav__link');

    const highlightNav = () => {
        const scrollPos = window.scrollY + 150;
        let currentSection = '';

        sections.forEach(section => {
            const top = section.offsetTop;
            const bottom = top + section.offsetHeight;
            let id = section.getAttribute('id');
            
            // Special handling for hero section
            if (section.classList.contains('hero')) {
                id = 'home';
            }

            if (scrollPos >= top && scrollPos <= bottom) {
                currentSection = id;
            }
        });

        navLinks.forEach(link => {
            link.classList.remove('active');
            const href = link.getAttribute('href');
            if (href === #${currentSection}) {
                link.classList.add('active');
            }
        });
    };

    window.addEventListener('scroll', highlightNav);
    // Initial highlight
    setTimeout(highlightNav, 100);
}

// Add CSS for active nav state
const style = document.createElement('style');
style.textContent = `
    .nav__link.active {
        color: var(--military-cyan) !important;
        background: rgba(0, 212, 255, 0.15) !important;
    }
    
    .hero {
        scroll-margin-top: 80px;
    }
    
    section {
        scroll-margin-top: 80px;
    }
`;
document.head.appendChild(style);

// Scroll animations for cards and elements
function initScrollAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    // Elements to animate on scroll
    const animatedElements = document.querySelectorAll(`
        .feature-card,
        .problem-card,
        .impl-card,
        .future-card,
        .tech-category,
        .team-member
    `);

    // Set initial state and observe
    animatedElements.forEach((element, index) => {
        element.style.opacity = '0';
        element.style.transform = 'translateY(30px)';
        element.style.transition = all 0.6s ease ${index * 0.1}s;
        observer.observe(element);
    });
}

// Header background on scroll
window.addEventListener('scroll', function() {
    const header = document.querySelector('.header');
    const scrolled = window.scrollY > 50;
    
    if (scrolled) {
        header.style.background = 'rgba(26, 26, 46, 0.98)';
        header.style.backdropFilter = 'blur(15px)';
    } else {
        header.style.background = 'rgba(26, 26, 46, 0.95)';
        header.style.backdropFilter = 'blur(10px)';
    }
});

// Add hover sound effect simulation (visual feedback)
document.querySelectorAll('.feature-card, .problem-card, .impl-card, .future-card, .team-member').forEach(card => {
    card.addEventListener('mouseenter', function() {
        this.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
    });
    
    card.addEventListener('mouseleave', function() {
        this.style.transition = 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)';
    });
});

// Button click effects
document.querySelectorAll('.btn').forEach(button => {
    button.addEventListener('click', function(e) {
        // Don't add ripple to external links
        if (this.getAttribute('target') === '_blank') {
            return;
        }
        
        // Create ripple effect for internal buttons
        const ripple = document.createElement('span');
        const rect = this.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;
        
        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            transform: scale(0);
            animation: ripple 0.6s linear;
            pointer-events: none;
        `;
        
        this.style.position = 'relative';
        this.style.overflow = 'hidden';
        this.appendChild(ripple);
        
        setTimeout(() => {
            ripple.remove();
        }, 600);
    });
});

// Add ripple animation CSS
const rippleStyle = document.createElement('style');
rippleStyle.textContent = `
    @keyframes ripple {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
`;
document.head.appendChild(rippleStyle);

// Performance optimization: throttle scroll events
function throttle(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Keyboard navigation support
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        document.activeElement.blur();
    }
    
    // Add keyboard navigation for accessibility
    if (e.key === 'Tab') {
        // Let default tab behavior work
    }
});

// Preload critical resources and optimize performance
window.addEventListener('load', function() {
    document.body.classList.add('loaded');
    
    // Test navigation after load
    setTimeout(() => {
        console.log('Zylo Tech website fully loaded and interactive');
        console.log('Navigation links found:', document.querySelectorAll('.nav__link').length);
        console.log('GitHub links found:', document.querySelectorAll('a[href*="github.com"]').length);
    }, 1000);
});

// Error handling for smooth user experience
window.addEventListener('error', function(e) {
    console.warn('Non-critical error caught:', e.error);
});

// Console message for developers
console.log(`
🔐 Zylo Tech - Secure Military Communication Tools
🚀 Website loaded successfully
⚡ All animations and interactions are ready
🛡 Quantum-resistant security protocols engaged
🔗 Navigation and GitHub links initialized
`);

// Export functions for debugging
window.ZyloTech = {
    initSmoothScrolling,
    initCounterAnimation,
    initNavHighlight,
    initScrollAnimations,
    initGitHubLinks,
    // Debug functions
    testNavigation: () => {
        console.log('Testing navigation...');
        document.querySelectorAll('.nav__link').forEach((link, i) => {
            console.log(Nav link ${i}:, link.getAttribute('href'), link.textContent);
        });
    },
    testGitHubLinks: () => {
        console.log('Testing GitHub links...');
        document.querySelectorAll('a[href*="github.com"]').forEach((link, i) => {
            console.log(GitHub link ${i}:, link.href, link.getAttribute('target'));
        });
    }
};
