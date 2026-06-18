document.addEventListener('DOMContentLoaded', () => {

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
    });

    // Mobile Menu Toggle
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const mobileNav = document.getElementById('mobile-nav');

    if (mobileMenuBtn && mobileNav) {
        mobileMenuBtn.addEventListener('click', () => {
            mobileMenuBtn.classList.toggle('active');
            mobileNav.classList.toggle('active');
            
            // Toggle hamburger animation
            const bars = mobileMenuBtn.querySelectorAll('.bar');
            if (mobileMenuBtn.classList.contains('active')) {
                bars[0].style.transform = 'rotate(-45deg) translate(-5px, 6px)';
                bars[1].style.opacity = '0';
                bars[2].style.transform = 'rotate(45deg) translate(-5px, -6px)';
            } else {
                bars[0].style.transform = 'none';
                bars[1].style.opacity = '1';
                bars[2].style.transform = 'none';
            }
        });
        
        // Close menu on link click
        mobileNav.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                mobileMenuBtn.classList.remove('active');
                mobileNav.classList.remove('active');
                mobileMenuBtn.querySelectorAll('.bar').forEach(b => b.style.transform = 'none');
                mobileMenuBtn.querySelector('.bar:nth-child(2)').style.opacity = '1';
            });
        });
    }

    // -------------------------------------------------------------
    // 2. Configuration Tabs
    // -------------------------------------------------------------
    const codeTabBtns = document.querySelectorAll('.code-tab-btn');
    const codePanels = document.querySelectorAll('.code-panel');

    codeTabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.getAttribute('data-target');
            
            // Toggle buttons
            codeTabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Toggle panels
            codePanels.forEach(p => p.classList.remove('active'));
            document.getElementById(target).classList.add('active');
        });
    });

    // -------------------------------------------------------------
    // 3. Clipboard Copy Functionality
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
                .then(() => showTooltip('Config copied to clipboard!'))
                .catch(() => showTooltip('Failed to copy'));
        });
    });

    // -------------------------------------------------------------
    // 4. Interactive Terminal Simulator
    // -------------------------------------------------------------
    const terminalContent = document.getElementById('terminal-content');
    const tabScan = document.getElementById('btn-tab-scan');
    const tabBaseline = document.getElementById('btn-tab-baseline');
    const tabDiff = document.getElementById('btn-tab-diff');
    const runBtn = document.getElementById('btn-run-terminal');

    let currentCommand = 'scan';
    let typingInterval = null;
    let sequenceTimeout = null;

    // Simulation Data definitions
    const simulations = {
        scan: {
            command: 'php artisan scalpel:scan',
            lines: [
                { type: 'output', text: '<span class="t-muted">Running structural anomaly scanner...</span> <span class="t-success">[OK]</span>' },
                { type: 'output', text: '<span class="t-muted">Running obfuscated code scanner...</span> <span class="t-crit">[SUSPICIOUS]</span>' },
                { type: 'output', text: '<span class="t-muted">Running htaccess scanner...</span> <span class="t-success">[OK]</span>' },
                { type: 'output', text: '<span class="t-muted">Running env integrity scanner...</span> <span class="t-success">[OK]</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-header">+-------------------------------------+----------+-------------------------------------+</span>' },
                { type: 'output', text: '<span class="t-header">| File Path                           | Severity | Finding                             |</span>' },
                { type: 'output', text: '<span class="t-header">+-------------------------------------+----------+-------------------------------------+</span>' },
                { type: 'output', text: '| <span class="t-high">public/icons/avatar.php</span>             | <span class="t-crit">CRITICAL</span> | eval(base64_decode) backdoor found  |' },
                { type: 'output', text: '| <span class="t-muted">storage/framework/cache/import.php</span>  | <span class="t-high">HIGH</span>     | Long encoded string (610 chars)     |' },
                { type: 'output', text: '<span class="t-header">+-------------------------------------+----------+-------------------------------------+</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-crit">Scan completed in 0.12s. Found 2 issues (1 CRITICAL, 1 HIGH).</span>' },
                { type: 'output', text: '<span class="t-muted">Exit code: 1</span>' }
            ]
        },
        baseline: {
            command: 'php artisan scalpel:baseline',
            lines: [
                { type: 'output', text: 'Scanning project files for baseline snapshot...' },
                { type: 'output', text: 'Calculating cryptographic SHA-256 hashes...' },
                { type: 'output', text: 'Ignoring configured exclusions:' },
                { type: 'output', text: '  - storage/logs/*' },
                { type: 'output', text: '  - storage/framework/cache/*' },
                { type: 'output', text: '  - node_modules/*' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-success">✔ Baseline snapshot generated successfully!</span>' },
                { type: 'output', text: 'Stored in: <span class="t-cyan">storage/app/private/scalpel/baseline.json</span> (482 files indexed)' },
                { type: 'output', text: '<span class="t-muted">Exit code: 0</span>' }
            ]
        },
        diff: {
            command: 'php artisan scalpel:diff',
            lines: [
                { type: 'output', text: 'Loading baseline snapshot... <span class="t-success">[OK]</span>' },
                { type: 'output', text: 'Comparing current filesystem against baseline...' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-header">+-------------------------+-----------+-------------------------+</span>' },
                { type: 'output', text: '<span class="t-header">| File Path               | Status    | Severity                |</span>' },
                { type: 'output', text: '<span class="t-header">+-------------------------+-----------+-------------------------+</span>' },
                { type: 'output', text: '| <span class="t-high">public/icons/avatar.php</span> | <span class="t-crit">ADDED</span>     | <span class="t-crit">CRITICAL (Backdoor)</span>     |' },
                { type: 'output', text: '| <span class="t-high">.env</span>                    | <span class="t-high">MODIFIED</span>  | <span class="t-high">HIGH (Tampered)</span>         |' },
                { type: 'output', text: '| <span class="t-muted">config/app.php</span>          | <span class="t-low">MODIFIED</span>  | LOW (Updated config)    |' },
                { type: 'output', text: '| <span class="t-muted">tests/TestCase.php</span>      | <span class="t-med">DELETED</span>   | MEDIUM                  |' },
                { type: 'output', text: '<span class="t-header">+-------------------------+-----------+-------------------------+</span>' },
                { type: 'output', text: '' },
                { type: 'output', text: '<span class="t-crit">Baseline diff comparison finished.</span>' },
                { type: 'output', text: 'Detected: <span class="t-crit">1 Added</span>, <span class="t-med">1 Deleted</span>, <span class="t-high">2 Modified</span> files.' },
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
        }, 50); // Speed of typing
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
                const delay = line.text === '' ? 150 : Math.random() * 80 + 40;
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
    tabScan.addEventListener('click', () => {
        toggleTab(tabScan, 'scan');
    });

    tabBaseline.addEventListener('click', () => {
        toggleTab(tabBaseline, 'baseline');
    });

    tabDiff.addEventListener('click', () => {
        toggleTab(tabDiff, 'diff');
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
    // 5. Bento Card Mouse Hover Glow Spell Effect
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
});
