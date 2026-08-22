document.addEventListener('DOMContentLoaded', () => {

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // -------------------------------------------------------------
    // 1. Navigation & Scroll Effects
    // -------------------------------------------------------------
    const header = document.getElementById('main-header');
    window.addEventListener('scroll', () => {
        if (window.scrollY > 20) {
            header.classList.add('scrolled');
        } else {
            header.classList.remove('scrolled');
        }
    }, { passive: true });

    // Mobile Menu Toggle
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const mobileNav = document.getElementById('mobile-nav');

    function setMobileMenu(open) {
        if (!mobileMenuBtn || !mobileNav) {
            return;
        }

        mobileMenuBtn.classList.toggle('active', open);
        mobileNav.classList.toggle('active', open);
        mobileMenuBtn.setAttribute('aria-expanded', String(open));

        const bars = mobileMenuBtn.querySelectorAll('.bar');
        if (open) {
            bars[0].style.transform = 'rotate(-45deg) translate(-5px, 6px)';
            bars[1].style.opacity = '0';
            bars[2].style.transform = 'rotate(45deg) translate(-5px, -6px)';
        } else {
            bars[0].style.transform = 'none';
            bars[1].style.opacity = '1';
            bars[2].style.transform = 'none';
        }
    }

    if (mobileMenuBtn && mobileNav) {
        mobileMenuBtn.addEventListener('click', () => {
            setMobileMenu(!mobileNav.classList.contains('active'));
        });

        // Close menu on link click or Escape
        mobileNav.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => setMobileMenu(false));
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && mobileNav.classList.contains('active')) {
                setMobileMenu(false);
                mobileMenuBtn.focus();
            }
        });
    }

    // -------------------------------------------------------------
    // 2. Accessible Tab Groups (arrow-key roving focus)
    // -------------------------------------------------------------
    function setupTabGroup(tablistSelector) {
        const tablist = document.querySelector(tablistSelector);

        if (!tablist) {
            return;
        }

        const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));

        tablist.addEventListener('keydown', (e) => {
            if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') {
                return;
            }

            e.preventDefault();

            const currentIndex = tabs.indexOf(document.activeElement);
            if (currentIndex === -1) {
                return;
            }

            const delta = e.key === 'ArrowRight' ? 1 : -1;
            const nextTab = tabs[(currentIndex + delta + tabs.length) % tabs.length];

            nextTab.focus();
            nextTab.click();
        });
    }

    setupTabGroup('.terminal-tabs');
    setupTabGroup('.code-tabs-sidebar');

    // -------------------------------------------------------------
    // 3. Configuration Tabs
    // -------------------------------------------------------------
    const codeTabBtns = document.querySelectorAll('.code-tab-btn');
    const codePanels = document.querySelectorAll('.code-panel');

    codeTabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.getAttribute('data-target');

            // Toggle buttons
            codeTabBtns.forEach(b => b.setAttribute('aria-selected', 'false'));
            btn.setAttribute('aria-selected', 'true');

            // Toggle panels
            codePanels.forEach(p => p.classList.remove('active'));
            document.getElementById(target).classList.add('active');
        });
    });

    // -------------------------------------------------------------
    // 4. Clipboard Copy Functionality
    // -------------------------------------------------------------
    const tooltip = document.getElementById('copy-tooltip');

    function showTooltip(message = 'Copied!') {
        tooltip.textContent = message;
        tooltip.classList.add('show');
        setTimeout(() => {
            tooltip.classList.remove('show');
        }, 2000);
    }

    // Copying command inputs
    const copyInputBtns = document.querySelectorAll('.btn-copy-input');
    copyInputBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const textToCopy = btn.getAttribute('data-copy');
            navigator.clipboard.writeText(textToCopy)
                .then(() => showTooltip('Command copied!'))
                .catch(() => showTooltip('Failed to copy'));
        });
    });

    // Copying config file contents
    const copyCodeBtns = document.querySelectorAll('.btn-copy-code');
    copyCodeBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const elementId = btn.getAttribute('data-clipboard');
            const codeText = document.getElementById(elementId).innerText;
            navigator.clipboard.writeText(codeText)
                .then(() => showTooltip('Code copied to clipboard!'))
                .catch(() => showTooltip('Failed to copy'));
        });
    });

    // -------------------------------------------------------------
    // 5. Interactive Terminal Simulator
    // -------------------------------------------------------------
    const terminalContent = document.getElementById('terminal-content');
    const runBtn = document.getElementById('btn-run-terminal');

    let currentCommand = 'scan';
    let typingInterval = null;
    let sequenceTimeout = null;

    // Simulation Data definitions (mirrors real CLI output)
    const simulations = {
        scan: {
            command: 'php artisan scalpel:scan',
            lines: [
                { type: 'output', text: '<span class="t-muted">  ╔══════════════════════════════════════════════════╗</span>' },
                { type: 'output', text: '<span class="t-muted">  ║</span> 🔬 <span class="t-cyan">Laravel Scalpel</span> — Intrusion Evidence Scanner <span class="t-muted">║</span>' },
                { type: 'output', text: '<span class="t-muted">  ╚══════════════════════════════════════════════════╝</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-cyan">  ▸</span> Running scanner: <span class="t-header">Structural Anomaly</span>' },
                { type: 'output', text: '<span class="t-cyan">  ▸</span> Running scanner: <span class="t-header">Obfuscated Code</span>' },
                { type: 'output', text: '<span class="t-cyan">  ▸</span> Running scanner: <span class="t-header">Htaccess</span>' },
                { type: 'output', text: '<span class="t-cyan">  ▸</span> Running scanner: <span class="t-header">Baseline Diff</span>' },
                { type: 'output', text: '<span class="t-cyan">  ▸</span> Running scanner: <span class="t-header">Env Integrity</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-crit">  🔴 CRITICAL</span> <span class="t-muted">(1 findings)</span>' },
                { type: 'output', text: '<span class="t-muted">  +---------------------------+------+------------------------------------------------+</span>' },
                { type: 'output', text: '<span class="t-muted">  | File                      | Line | Description                                    |</span>' },
                { type: 'output', text: '<span class="t-muted">  +---------------------------+------+------------------------------------------------+</span>' },
                { type: 'output', text: '  | 🔴 public/icons/avatar.php | 1    | eval(base64_decode(...)) detected — classic...' } ,
                { type: 'output', text: '<span class="t-muted">  +---------------------------+------+------------------------------------------------+</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-high">  🟠 HIGH</span> <span class="t-muted">(1 findings)</span>' },
                { type: 'output', text: '  | 🟠 public/js/app.min.php   | -    | PHP file (\'.php\') found in non-PHP zone \'public\'.' },
                { type: 'output', text: '' },
                { type: 'output', text: '  <span class="t-header">📊 Summary by Scanner</span>' },
                { type: 'output', text: '  Obfuscated Code ......... 1' },
                { type: 'output', text: '  Structural Anomaly ...... 1' },
                { type: 'output', text: '' },
                { type: 'output', text: '  Total findings: <span class="t-header">2</span>' },
                { type: 'output', text: '<span class="t-crit">  ⚠  CRITICAL or HIGH severity findings detected. Investigate immediately!</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-muted">Exit code: 1</span>' }
            ]
        },
        baseline: {
            command: 'php artisan scalpel:baseline --force',
            lines: [
                { type: 'output', text: '<span class="t-cyan">  ▸</span> Creating baseline snapshot...' },
                { type: 'output', text: '  <span class="t-muted">12,847/12,847 [████████████████████] 100% -- Complete!</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-success">  ✅ Baseline snapshot created successfully.</span>' },
                { type: 'output', text: '  Files indexed : <span class="t-header">12,847</span>' },
                { type: 'output', text: '  Total size    : <span class="t-header">214.6 MB</span>' },
                { type: 'output', text: '  Stored in     : <span class="t-cyan">storage/app/private/scalpel/baseline.json</span>' },
                { type: 'output', text: '  HMAC signed   : <span class="t-success">yes</span> <span class="t-muted">(tampering will be detected by scalpel:diff)</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-muted">Exit code: 0</span>' }
            ]
        },
        diff: {
            command: 'php artisan scalpel:diff',
            lines: [
                { type: 'output', text: '<span class="t-cyan">  ▸</span> Comparing filesystem against baseline...' },
                { type: 'output', text: '  <span class="t-muted">12,851/12,847 [████████████████████] 100% -- Complete!</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-crit">  🔴 CRITICAL</span> <span class="t-muted">(1 findings)</span>' },
                { type: 'output', text: '  | 🔴 .env                     | -    | File has been deleted since baseline snapshot.' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-high">  🟠 HIGH</span> <span class="t-muted">(2 findings)</span>' },
                { type: 'output', text: '  | 🟠 public/icons/avatar.php  | -    | New file detected that was not in the baseline snapshot.' },
                { type: 'output', text: '  | 🟠 routes/web.php           | -    | File has been modified since baseline (hash mismatch).' },
                { type: 'output', text: '' },
                { type: 'output', text: '  Total changes detected: <span class="t-header">3</span>' },
                { type: 'output', text: '<span class="t-crit">  ⚠  CRITICAL or HIGH severity changes detected. Investigate immediately!</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-muted">Exit code: 1</span>' }
            ]
        },
        verify: {
            command: 'php artisan scalpel:verify storage/scalpel-output.json',
            lines: [
                { type: 'output', text: '<span class="t-success">  ✅ Output integrity verified successfully.</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-muted">Exit code: 0</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="terminal-prompt-inline">hryagstn@vps:~/laravel-scalpel$</span> php artisan scalpel:verify tampered-output.json' },
                { type: 'output', text: '<span class="t-crit">  ❌ Signature verification failed. The payload has been tampered with</span>' },
                { type: 'output', text: '<span class="t-crit">     or signed with a different key.</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-muted">Exit code: 1</span>' }
            ]
        }
    };

    function clearSimulation() {
        if (typingInterval) clearInterval(typingInterval);
        if (sequenceTimeout) clearTimeout(sequenceTimeout);
        terminalContent.innerHTML = '';
    }

    function runSimulation(simKey) {
        clearSimulation();
        const sim = simulations[simKey];

        // 1. Render prompt line
        const inputLine = document.createElement('div');
        inputLine.className = 'terminal-input-line';
        inputLine.innerHTML = `
            <span class="terminal-prompt">hryagstn@vps:~/laravel-scalpel$</span>
            <span class="terminal-command-container">
                <span class="terminal-command"></span><span class="terminal-cursor"></span>
            </span>
        `;
        terminalContent.appendChild(inputLine);

        const cmdSpan = inputLine.querySelector('.terminal-command');
        const cursor = inputLine.querySelector('.terminal-cursor');

        let charIndex = 0;
        const commandText = sim.command;

        // Respect reduced motion: render instantly instead of typing
        if (prefersReducedMotion) {
            cmdSpan.textContent = commandText;
            cursor.remove();
            renderOutputs(sim.lines);
            return;
        }

        // 2. Typing animation for command
        typingInterval = setInterval(() => {
            if (charIndex < commandText.length) {
                cmdSpan.textContent += commandText[charIndex];
                charIndex++;
            } else {
                clearInterval(typingInterval);
                cursor.remove(); // Remove active prompt cursor

                // Trigger outputs
                sequenceTimeout = setTimeout(() => {
                    renderOutputs(sim.lines);
                }, 400);
            }
        }, 40); // Speed of typing
    }

    function renderOutputs(lines) {
        let lineIndex = 0;

        function printNextLine() {
            if (lineIndex < lines.length) {
                const line = lines[lineIndex];
                const lineDiv = document.createElement('div');
                lineDiv.className = 'terminal-output';
                lineDiv.innerHTML = line.text;
                terminalContent.appendChild(lineDiv);

                // Auto Scroll
                terminalContent.scrollTop = terminalContent.scrollHeight;

                lineIndex++;
                // Variables speeds for output generation for realistic shell simulation
                const delay = prefersReducedMotion ? 0 : (line.text === '' ? 150 : Math.random() * 80 + 40);
                sequenceTimeout = setTimeout(printNextLine, delay);
            } else {
                // Done printing lines, append empty prompt and a blinking cursor at the bottom
                const promptLine = document.createElement('div');
                promptLine.className = 'terminal-input-line';
                promptLine.style.marginTop = '1rem';
                promptLine.innerHTML = `
                    <span class="terminal-prompt">hryagstn@vps:~/laravel-scalpel$</span>
                    <span class="terminal-command-container"><span class="terminal-cursor"></span></span>
                `;
                terminalContent.appendChild(promptLine);
                terminalContent.scrollTop = terminalContent.scrollHeight;
            }
        }

        printNextLine();
    }

    // Event Handlers for Terminal Tabs
    const terminalTabs = {
        'btn-tab-scan': 'scan',
        'btn-tab-baseline': 'baseline',
        'btn-tab-diff': 'diff',
        'btn-tab-verify': 'verify',
    };

    Object.entries(terminalTabs).forEach(([btnId, simKey]) => {
        const btn = document.getElementById(btnId);

        if (!btn) {
            return;
        }

        btn.addEventListener('click', () => toggleTab(btn, simKey));
    });

    function toggleTab(clickedTab, simKey) {
        if (currentCommand === simKey && terminalContent.children.length > 0) return;

        // Update tabs active state
        document.querySelectorAll('.terminal-tab-btn').forEach(btn => {
            btn.classList.remove('active');
            btn.setAttribute('aria-selected', 'false');
        });
        clickedTab.classList.add('active');
        clickedTab.setAttribute('aria-selected', 'true');

        currentCommand = simKey;
        runSimulation(simKey);
    }

    runBtn.addEventListener('click', () => {
        runSimulation(currentCommand);
    });

    // Run scan simulation by default on page load
    runSimulation('scan');

    // -------------------------------------------------------------
    // 6. Bento Card Mouse Hover Glow Spell Effect
    // -------------------------------------------------------------
    const cards = document.querySelectorAll('.scanner-card');
    cards.forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            card.style.setProperty('--x', `${x}px`);
            card.style.setProperty('--y', `${y}px`);
        });
    });

    // -------------------------------------------------------------
    // 7. Dynamic Version Tag Fetcher
    // -------------------------------------------------------------
    async function fetchLatestVersion() {
        try {
            const response = await fetch('https://api.github.com/repos/hryagstn/laravel-scalpel/releases/latest');

            if (! response.ok) {
                return;
            }

            const release = await response.json();
            const latestVersion = release && release.tag_name;

            // Only accept well-formed version tags
            if (latestVersion && /^v?\d+\.\d+\.\d+$/.test(latestVersion)) {
                document.querySelectorAll('.badge-version').forEach(el => {
                    el.textContent = latestVersion.startsWith('v') ? latestVersion : `v${latestVersion}`;
                });
            }
        } catch (error) {
            console.warn('Failed to fetch latest release version from GitHub:', error);
        }
    }
    fetchLatestVersion();

    // -------------------------------------------------------------
    // 8. Dynamic Copyright Year
    // -------------------------------------------------------------
    const yearEl = document.getElementById('copyright-year');

    if (yearEl) {
        yearEl.textContent = String(new Date().getFullYear());
    }
});
