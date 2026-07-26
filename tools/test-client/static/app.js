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

    const sendWS = (msg) => ws && isConnected && ws.send(JSON.stringify(msg));

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
    };

    const initiateRequest = async () => {
        await activateNode(nodes.pc, "Test Client initiating request...");
        deactivateNode(nodes.pc);
        $('uart-tx')?.classList.add('active');
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

    window.addEventListener('scroll', () => {
        if (isRemoteScrolling || !ws || !isConnected) return;
        if (scrollRaf) cancelAnimationFrame(scrollRaf);
        scrollRaf = requestAnimationFrame(() => {
            sendWS({ type: 'scroll', scrollY: window.scrollY });
        });
    }, { passive: true });

    const handleRemoteScroll = (y) => {
        isRemoteScrolling = true;
        window.scrollTo({ top: y, behavior: 'smooth' });
        setTimeout(() => { isRemoteScrolling = false; }, 300);
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
                switch (msg.type) {
                    case 'init':
                        if (msg.clientCount) updateClientCountUI(msg.clientCount);
                        if (msg.nonce && nonceInput && !nonceInput.value) nonceInput.value = msg.nonce;
                        if (msg.data && !isAnimating) displayResults(msg.data);
                        if (msg.tokenSrc && statusText && !isAnimating) {
                            statusText.innerText = `Ready (Data Source: ${msg.tokenSrc.toUpperCase()})`;
                        }
                        if (typeof msg.scrollY === 'number' && msg.scrollY > 0) handleRemoteScroll(msg.scrollY);
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
                        if (typeof msg.scrollY === 'number') handleRemoteScroll(msg.scrollY);
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
