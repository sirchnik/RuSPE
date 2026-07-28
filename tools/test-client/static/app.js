// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

document.addEventListener('DOMContentLoaded', () => {
    const $ = id => document.getElementById(id);

    const fetchBtn = $('fetch-btn');
    const statusText = $('status-text');
    const resultsSection = $('results-section');
    const nonceInput = $('nonce-input');
    const regenNonceBtn = $('regen-nonce-btn');
    const wsDot = $('ws-dot');
    const wsStatusText = $('ws-status-text');
    const secretDotBtn = $('secret-dot-btn');
    const svg = $('trail-svg');
    const systemContainer = $('system-container');

    const nodes = {
        pc: $('node-pc'),
        app: $('node-app'),
        kernel: $('node-kernel'),
        spe: $('node-spe'),
        attest: $('node-attest'),
        crypto: $('node-crypto')
    };

    let ws = null;
    let isConnected = false;
    let isAnimating = false;
    let pendingResult = null;
    let trailConnections = [];
    let isRemoteScrolling = false;
    let scrollRaf = null;

    const generateRandomNonce = () => {
        const arr = new Uint8Array(32);
        window.crypto.getRandomValues(arr);
        return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    };

    const myClientId = 'c_' + Math.random().toString(36).substring(2, 9);
    const COLOR_PALETTE = ['#3b82f6', '#10b981', '#f59e0b', '#ec4899', '#8b5cf6', '#06b6d4', '#f97316', '#e11d48'];

    const getClientColor = (id) => {
        let hash = 0;
        for (let i = 0; i < id.length; i++) hash = id.charCodeAt(i) + ((hash << 5) - hash);
        return COLOR_PALETTE[Math.abs(hash) % COLOR_PALETTE.length];
    };

    const sendWS = (msg) => {
        if (ws && isConnected) {
            if (!msg.senderId) msg.senderId = myClientId;
            ws.send(JSON.stringify(msg));
        }
    };

    const updateNonce = (val) => {
        if (nonceInput) nonceInput.value = val;
        sendWS({ type: 'update_nonce', nonce: val });
    };

    if (nonceInput) {
        if (!nonceInput.value) nonceInput.value = generateRandomNonce();
        nonceInput.addEventListener('input', () => updateNonce(nonceInput.value.trim()));
    }

    if (regenNonceBtn) {
        regenNonceBtn.addEventListener('click', () => updateNonce(generateRandomNonce()));
    }

    const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

    const activateNode = async (node, text) => {
        if (text) statusText.innerText = text;
        node.classList.add('active');
        await sleep(500);
    };

    const deactivateNode = (node) => node.classList.remove('active');

    const getCenter = (node) => {
        const rect = node.getBoundingClientRect();
        const containerRect = systemContainer.getBoundingClientRect();
        return {
            x: rect.left - containerRect.left + rect.width / 2,
            y: rect.top - containerRect.top + rect.height / 2
        };
    };

    const drawLine = (node1, node2, isBack = false, isSolid = false) => {
        const p1 = getCenter(node1);
        const p2 = getCenter(node2);
        const dx = p2.x - p1.x;
        const dy = p2.y - p1.y;
        const length = Math.sqrt(dx * dx + dy * dy);
        if (length === 0) return;

        const offset = 8;
        const nx = (-dy / length) * offset;
        const ny = (dx / length) * offset;

        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', p1.x + nx);
        line.setAttribute('y1', p1.y + ny);
        line.setAttribute('x2', p2.x + nx);
        line.setAttribute('y2', p2.y + ny);
        line.setAttribute('stroke', isBack ? '#10b981' : '#3b82f6');
        line.setAttribute('stroke-width', '4');

        if (isSolid) {
            line.setAttribute('stroke-dasharray', 'none');
        } else {
            line.setAttribute('stroke-dasharray', '8 8');
            line.classList.add('trail-line');
            line.style.animation = 'dashAnim 1s linear infinite';
            setTimeout(() => { if (line.parentNode) line.style.animationPlayState = 'paused'; }, 2000);
        }
        svg.appendChild(line);
    };

    const redrawTrail = () => {
        svg.innerHTML = '';
        trailConnections.forEach(pair => drawLine(pair[0], pair[1], pair[2], pair[3]));
    };

    window.addEventListener('resize', redrawTrail);

    const addTrailSegment = (n1, n2, isBack = false, isSolid = false) => {
        trailConnections.push([n1, n2, isBack, isSolid]);
        drawLine(n1, n2, isBack, isSolid);
        n1.classList.add('trail');
        n2.classList.add('trail');
    };

    const clearTrail = () => {
        svg.innerHTML = '';
        trailConnections = [];
        Object.values(nodes).forEach(n => n.classList.remove('trail', 'active'));
        ['uart-tx', 'uart-rx'].forEach(id => $(id)?.classList.remove('active'));
        $('uart-tx-badge')?.classList.remove('active', 'animating-tx');
        $('uart-rx-badge')?.classList.remove('active', 'animating-rx');
    };

    const initiateRequest = async () => {
        await activateNode(nodes.pc, "Test Client initiating request...");
        deactivateNode(nodes.pc);
        $('uart-tx')?.classList.add('active');
        const txBadge = $('uart-tx-badge');
        if (txBadge) {
            txBadge.classList.remove('animating-tx');
            void txBadge.offsetWidth;
            txBadge.classList.add('active', 'animating-tx');
        }
        nodes.pc.classList.add('active');
        statusText.innerText = "Waiting for device response over UART...";
    };

    const animateChipProcessing = async () => {
        nodes.pc.classList.remove('active');
        await activateNode(nodes.app, "Tock App receiving request over UART...");
        deactivateNode(nodes.app);

        const steps = [
            [nodes.app, nodes.spe, "Tock App calling SPE directly..."],
            [nodes.spe, nodes.attest, "Attestation Service gathering claims..."],
            [nodes.attest, nodes.crypto, "Crypto Service signing the token..."]
        ];
        for (const [from, to, text] of steps) {
            addTrailSegment(from, to);
            await activateNode(to, text);
            if (to !== nodes.crypto) deactivateNode(to);
        }
        await sleep(400);
    };

    const playBackwardAnimation = async () => {
        statusText.innerText = "Signature generated, returning token...";
        deactivateNode(nodes.crypto);

        const steps = [
            [nodes.crypto, nodes.attest, "Attestation Service assembling token..."],
            [nodes.attest, nodes.spe, "SPE returning token directly to Tock App..."],
            [nodes.spe, nodes.app, "Tock App passing token over UART..."]
        ];
        for (const [from, to, text] of steps) {
            addTrailSegment(from, to, true);
            await activateNode(to, text);
            deactivateNode(to);
        }

        $('uart-rx')?.classList.add('active');
        const rxBadge = $('uart-rx-badge');
        if (rxBadge) {
            rxBadge.classList.remove('animating-rx');
            void rxBadge.offsetWidth;
            rxBadge.classList.add('active', 'animating-rx');
        }
        await activateNode(nodes.pc, "Test Client received token!");
        await sleep(800);
        deactivateNode(nodes.pc);
        statusText.innerText = "Token flow complete.";
    };

    const displayResults = (data) => {
        if (!data) return;
        resultsSection.classList.remove('hidden');

        const vCard = $('verification-card');
        const vTitle = $('verification-title');
        const vMsg = $('verification-msg');

        if (data.error || !data.verification_status) {
            vCard.className = 'card verification-card error';
            vTitle.innerText = data.error ? 'Error Occurred' : 'Token Verification Failed';
            vMsg.innerText = data.error || data.verification_error || 'Invalid signature';
            if (data.error) return;
        } else {
            vCard.className = 'card verification-card success';
            vTitle.innerText = 'Token Verification Successful';
            vMsg.innerText = 'The ECDSA signature is valid and claims are trusted.';
        }

        const claimsGrid = $('claims-grid');
        const claims = [
            ['Profile', data.profile],
            ['Instance ID', data.instance_id],
            ['Implementation ID', data.implementation_id],
            ['Client ID', data.client_id !== undefined ? data.client_id.toString() : null],
            ['Security Lifecycle', data.security_lifecycle !== undefined ? `0x${data.security_lifecycle.toString(16)}` : null],
            ['Boot Seed', data.boot_seed],
            ['Nonce', data.nonce],
            ['Cert Reference', data.certification_reference],
            ['VSI', data.vsi]
        ];
        claimsGrid.innerHTML = claims
            .filter(([_, v]) => v)
            .map(([l, v]) => `<div class="claim-item"><div class="claim-label">${l}</div><div class="claim-value">${v}</div></div>`)
            .join('');

        const swContainer = $('sw-components-container');
        const swList = $('sw-components-list');

        if (data.software_components && data.software_components.length > 0) {
            swContainer.style.display = 'block';
            swList.innerHTML = data.software_components.map(comp => `
                <div class="sw-component">
                    ${[
                    ['Measurement Type', comp.measurement_type],
                    ['Measurement Value', comp.measurement_value],
                    ['Signer ID', comp.signer_id],
                    ['Version', comp.version],
                    ['Description', comp.measurement_desc]
                ].filter(([_, v]) => v).map(([l, v]) => `<div class="claim-item"><div class="claim-label">${l}</div><div class="claim-value">${v}</div></div>`).join('')}
                </div>
            `).join('');
        } else {
            swContainer.style.display = 'none';
        }
    };

    const handleTokenStarted = async (nonce) => {
        fetchBtn.disabled = true;
        if (nonce && nonceInput) nonceInput.value = nonce;
        resultsSection.classList.add('hidden');
        clearTrail();
        isAnimating = true;
        pendingResult = null;
        await initiateRequest();

        if (pendingResult) {
            const res = pendingResult;
            pendingResult = null;
            await handleTokenResult(res);
        }
    };

    const handleTokenResult = async (data) => {
        if (isAnimating && statusText.innerText.includes("Test Client initiating request...")) {
            pendingResult = data;
            return;
        }

        if (!data.error) {
            await animateChipProcessing();
            await playBackwardAnimation();
        } else {
            nodes.pc.classList.remove('active');
            statusText.innerText = "Error requesting token: " + data.error;
        }

        displayResults(data);
        fetchBtn.disabled = false;
        isAnimating = false;
    };

    let isLocalScrolling = false;
    let localScrollTimeout = null;
    let mouseRaf = null;
    const remoteCursors = {};
    const cursorTimeouts = {};

    const sendMouseState = (xPercent, pageY, visible, isClick = false) => {
        if (!ws || !isConnected) return;
        sendWS({
            type: 'mouse',
            senderId: myClientId,
            mouseX: xPercent,
            mouseY: pageY,
            mouseVisible: visible,
            isClick: isClick
        });
    };

    document.addEventListener('mousemove', (e) => {
        if (mouseRaf) cancelAnimationFrame(mouseRaf);
        mouseRaf = requestAnimationFrame(() => {
            const xPercent = (e.clientX / window.innerWidth) * 100;
            sendMouseState(xPercent, e.pageY, true);
        });
    }, { passive: true });

    document.addEventListener('mouseleave', () => sendMouseState(0, 0, false));
    window.addEventListener('blur', () => sendMouseState(0, 0, false));

    document.addEventListener('click', (e) => {
        const xPercent = (e.clientX / window.innerWidth) * 100;
        sendMouseState(xPercent, e.pageY, true, true);
    });

    const handleRemoteMouse = (msg) => {
        if (!msg || !msg.senderId || msg.senderId === myClientId) return;

        const id = msg.senderId;
        let cursorEl = remoteCursors[id];

        if (!cursorEl) {
            const color = getClientColor(id);
            cursorEl = document.createElement('div');
            cursorEl.className = 'remote-cursor';
            cursorEl.id = `cursor-${id}`;
            cursorEl.style.setProperty('--cursor-color', color);
            cursorEl.innerHTML = `
                <svg class="cursor-pointer" viewBox="0 0 24 24" width="20" height="20">
                    <path fill="${color}" stroke="#ffffff" stroke-width="1.5" stroke-linejoin="round" d="M3 3l7 18 3-7 7-3L3 3z"/>
                </svg>
            `;
            document.body.appendChild(cursorEl);
            remoteCursors[id] = cursorEl;
        }

        if (cursorTimeouts[id]) clearTimeout(cursorTimeouts[id]);

        if (msg.mouseVisible) {
            const targetX = (msg.mouseX / 100) * window.innerWidth;
            const targetY = msg.mouseY;
            cursorEl.style.transform = `translate3d(${targetX}px, ${targetY}px, 0)`;
            cursorEl.classList.add('visible');

            if (msg.isClick) {
                const ripple = document.createElement('div');
                ripple.className = 'cursor-ripple';
                ripple.style.left = `${targetX}px`;
                ripple.style.top = `${targetY}px`;
                ripple.style.setProperty('--cursor-color', getClientColor(id));
                document.body.appendChild(ripple);
                setTimeout(() => ripple.remove(), 600);
            }

            cursorTimeouts[id] = setTimeout(() => {
                if (cursorEl) cursorEl.classList.remove('visible');
            }, 4000);
        } else {
            cursorEl.classList.remove('visible');
        }
    };

    let remoteScrollTimer = null;

    window.addEventListener('scroll', () => {
        if (isRemoteScrolling) return;

        isLocalScrolling = true;
        if (localScrollTimeout) clearTimeout(localScrollTimeout);
        localScrollTimeout = setTimeout(() => {
            isLocalScrolling = false;
        }, 100);

        if (!ws || !isConnected) return;

        if (scrollRaf) cancelAnimationFrame(scrollRaf);
        scrollRaf = requestAnimationFrame(() => {
            const maxScroll = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
            const currentY = window.scrollY;
            const isAtTop = currentY <= 35;
            const isAtBottom = maxScroll > 0 && (currentY + window.innerHeight >= document.documentElement.scrollHeight - 35);
            const scrollRatio = isAtBottom ? 1.0 : (isAtTop ? 0.0 : (maxScroll > 0 ? currentY / maxScroll : 0));

            sendWS({
                type: 'scroll',
                senderId: myClientId,
                scrollY: currentY,
                scrollRatio: scrollRatio,
                isAtBottom: isAtBottom,
                isAtTop: isAtTop
            });
        });
    }, { passive: true });

    const handleRemoteScroll = (data) => {
        if (!data || data.senderId === myClientId || isLocalScrolling) return;

        const maxScroll = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
        if (maxScroll <= 0) return;

        let targetY = data.scrollY;

        if (data.isAtBottom || (typeof data.scrollRatio === 'number' && data.scrollRatio >= 0.96)) {
            targetY = maxScroll;
        } else if (data.isAtTop || (typeof data.scrollRatio === 'number' && data.scrollRatio <= 0.04)) {
            targetY = 0;
        } else if (typeof data.scrollRatio === 'number') {
            targetY = data.scrollRatio * maxScroll;
        }

        targetY = Math.max(0, Math.min(targetY, maxScroll));

        isRemoteScrolling = true;
        window.scrollTo({ top: targetY, behavior: 'auto' });

        if (remoteScrollTimer) clearTimeout(remoteScrollTimer);
        remoteScrollTimer = setTimeout(() => {
            isRemoteScrolling = false;
        }, 100);
    };

    const updateClientCountUI = (count) => {
        if (wsStatusText) {
            wsStatusText.innerText = `${count} Connected Client${count > 1 ? 's' : ''}`;
        }
    };

    const connectWebSocket = () => {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

        ws.onopen = () => {
            isConnected = true;
            if (wsDot) wsDot.className = 'status-dot connected';
            if (wsStatusText) wsStatusText.innerText = 'Connected';
        };

        ws.onclose = () => {
            isConnected = false;
            if (wsDot) wsDot.className = 'status-dot disconnected';
            if (wsStatusText) wsStatusText.innerText = 'Disconnected - Retrying...';
            setTimeout(connectWebSocket, 2000);
        };

        ws.onerror = (err) => console.error('WebSocket Error:', err);

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.senderId && msg.senderId === myClientId) return;

                switch (msg.type) {
                    case 'init':
                        if (msg.clientCount) updateClientCountUI(msg.clientCount);
                        if (msg.nonce && nonceInput && !nonceInput.value) nonceInput.value = msg.nonce;
                        if (msg.data && !isAnimating) displayResults(msg.data);
                        if (msg.tokenSrc && statusText && !isAnimating) {
                            statusText.innerText = `Ready (Data Source: ${msg.tokenSrc.toUpperCase()})`;
                        }
                        if (typeof msg.scrollY === 'number' && msg.scrollY > 0) handleRemoteScroll(msg);
                        break;
                    case 'client_count':
                        updateClientCountUI(msg.clientCount);
                        break;
                    case 'token_started':
                        handleTokenStarted(msg.nonce);
                        break;
                    case 'token_result':
                        handleTokenResult(msg.data);
                        break;
                    case 'nonce_updated':
                        if (msg.nonce && nonceInput && nonceInput.value !== msg.nonce) {
                            nonceInput.value = msg.nonce;
                        }
                        break;
                    case 'scroll':
                        handleRemoteScroll(msg);
                        break;
                    case 'mouse':
                        handleRemoteMouse(msg);
                        break;
                    case 'source_switched':
                        if (statusText) {
                            statusText.innerText = `Data source switched to: ${msg.tokenSrc.toUpperCase()}`;
                        }
                        break;
                }
            } catch (e) {
                console.error('Error handling WebSocket message:', e);
            }
        };
    };

    connectWebSocket();

    const triggerTokenRequest = () => {
        sendWS({
            type: 'request_token',
            nonce: nonceInput ? nonceInput.value.trim() : ''
        });
    };

    const triggerToggleFake = () => sendWS({ type: 'switch_fake' });

    fetchBtn.addEventListener('click', triggerTokenRequest);

    document.addEventListener('keydown', (e) => {
        if (e.key === 'F' || e.key === 'f') triggerToggleFake();
    });

    if (secretDotBtn) secretDotBtn.addEventListener('click', triggerToggleFake);
});
