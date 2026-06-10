// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

document.addEventListener('DOMContentLoaded', () => {
    const fetchBtn = document.getElementById('fetch-btn');
    const statusText = document.getElementById('status-text');
    const resultsSection = document.getElementById('results-section');
    const nonceInput = document.getElementById('nonce-input');
    const regenNonceBtn = document.getElementById('regen-nonce-btn');

    const generateRandomNonce = () => {
        const arr = new Uint8Array(32);
        window.crypto.getRandomValues(arr);
        return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    };

    if (nonceInput) {
        nonceInput.value = generateRandomNonce();
    }

    if (regenNonceBtn && nonceInput) {
        regenNonceBtn.addEventListener('click', () => {
            nonceInput.value = generateRandomNonce();
        });
    }
    
    const nodes = {
        pc: document.getElementById('node-pc'),
        app: document.getElementById('node-app'),
        kernel: document.getElementById('node-kernel'),
        spe: document.getElementById('node-spe'),
        attest: document.getElementById('node-attest'),
        crypto: document.getElementById('node-crypto')
    };

    const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

    const activateNode = async (node, text) => {
        statusText.innerText = text;
        node.classList.add('active');
        await sleep(500);
    };

    const deactivateNode = (node) => {
        node.classList.remove('active');
    };

    const svg = document.getElementById('trail-svg');
    const systemContainer = document.getElementById('system-container');
    let trailConnections = [];

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
        
        let x1 = p1.x;
        let y1 = p1.y;
        let x2 = p2.x;
        let y2 = p2.y;

        // Offset the line so forward and backward paths don't perfectly overlap
        const dx = x2 - x1;
        const dy = y2 - y1;
        const length = Math.sqrt(dx * dx + dy * dy);
        const nx = -dy / length;
        const ny = dx / length;
        
        const offset = 8;
        x1 += nx * offset;
        y1 += ny * offset;
        x2 += nx * offset;
        y2 += ny * offset;
        
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', x1);
        line.setAttribute('y1', y1);
        line.setAttribute('x2', x2);
        line.setAttribute('y2', y2);
        
        if (isBack) {
            line.setAttribute('stroke', '#10b981'); // Green for return
        } else {
            line.setAttribute('stroke', '#3b82f6'); // Blue for forward
        }
        
        line.setAttribute('stroke-width', '4');
        if (isSolid) {
            line.setAttribute('stroke-dasharray', 'none');
        } else {
            line.setAttribute('stroke-dasharray', '8 8');
            line.classList.add('trail-line');
            line.style.animation = 'dashAnim 1s linear infinite';
            
            setTimeout(() => {
                if (line.parentNode) {
                    line.style.animationPlayState = 'paused';
                }
            }, 2000);
        }
        
        svg.appendChild(line);
    };

    const redrawTrail = () => {
        svg.innerHTML = '';
        trailConnections.forEach(pair => {
            drawLine(pair[0], pair[1], pair[2], pair[3]);
        });
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
        Object.values(nodes).forEach(n => n.classList.remove('trail'));
        const uartTx = document.getElementById('uart-tx');
        if (uartTx) uartTx.classList.remove('active');
        const uartRx = document.getElementById('uart-rx');
        if (uartRx) uartRx.classList.remove('active');
    };

    const initiateRequest = async () => {
        await activateNode(nodes.pc, "Test Client initiating request...");
        deactivateNode(nodes.pc);

        const uartTx = document.getElementById('uart-tx');
        if (uartTx) uartTx.classList.add('active');
        nodes.pc.classList.add('active');
        statusText.innerText = "Waiting for device response over UART...";
    };

    const animateChipProcessing = async () => {
        nodes.pc.classList.remove('active');
        await activateNode(nodes.app, "Tock App receiving request over UART...");
        deactivateNode(nodes.app);

        addTrailSegment(nodes.app, nodes.kernel);
        await activateNode(nodes.kernel, "Kernel routing request to SPE...");
        deactivateNode(nodes.kernel);

        addTrailSegment(nodes.kernel, nodes.spe);
        await activateNode(nodes.spe, "SPE delegating to Attestation Service...");
        deactivateNode(nodes.spe);

        addTrailSegment(nodes.spe, nodes.attest);
        await activateNode(nodes.attest, "Attestation Service gathering claims...");
        deactivateNode(nodes.attest);

        addTrailSegment(nodes.attest, nodes.crypto);
        await activateNode(nodes.crypto, "Crypto Service signing the token...");
        await sleep(400); // Simulating crypto work
    };

    const playBackwardAnimation = async () => {
        statusText.innerText = "Signature generated, returning token...";
        deactivateNode(nodes.crypto);

        addTrailSegment(nodes.crypto, nodes.attest, true);
        await activateNode(nodes.attest, "Attestation Service assembling token...");
        deactivateNode(nodes.attest);

        addTrailSegment(nodes.attest, nodes.spe, true);
        await activateNode(nodes.spe, "SPE returning token to Kernel...");
        deactivateNode(nodes.spe);

        addTrailSegment(nodes.spe, nodes.kernel, true);
        await activateNode(nodes.kernel, "Kernel passing token to User Space...");
        deactivateNode(nodes.kernel);

        addTrailSegment(nodes.kernel, nodes.app, true);
        await activateNode(nodes.app, "Tock App passing token over UART...");
        deactivateNode(nodes.app);

        const uartRx = document.getElementById('uart-rx');
        if (uartRx) uartRx.classList.add('active');
        
        await activateNode(nodes.pc, "Test Client received token!");
        await sleep(800);
        deactivateNode(nodes.pc);
        statusText.innerText = "Token flow complete.";
    };

    const displayResults = (data) => {
        resultsSection.classList.remove('hidden');
        
        const vCard = document.getElementById('verification-card');
        const vTitle = document.getElementById('verification-title');
        const vMsg = document.getElementById('verification-msg');

        if (data.error) {
            vCard.className = 'card verification-card error';
            vTitle.innerText = 'Error Occurred';
            vMsg.innerText = data.error;
            return;
        }

        if (data.verification_status) {
            vCard.className = 'card verification-card success';
            vTitle.innerText = 'Token Verification Successful';
            vMsg.innerText = 'The ECDSA signature is valid and claims are trusted.';
        } else {
            vCard.className = 'card verification-card error';
            vTitle.innerText = 'Token Verification Failed';
            vMsg.innerText = data.verification_error || 'Invalid signature';
        }

        // Render Claims
        const claimsGrid = document.getElementById('claims-grid');
        claimsGrid.innerHTML = '';
        
        const addClaim = (label, value) => {
            if (!value) return;
            const div = document.createElement('div');
            div.className = 'claim-item';
            div.innerHTML = `<div class="claim-label">${label}</div><div class="claim-value">${value}</div>`;
            claimsGrid.appendChild(div);
        };

        addClaim('Profile', data.profile);
        addClaim('Instance ID', data.instance_id);
        addClaim('Implementation ID', data.implementation_id);
        addClaim('Client ID', data.client_id !== undefined ? data.client_id.toString() : null);
        addClaim('Security Lifecycle', data.security_lifecycle !== undefined ? `0x${data.security_lifecycle.toString(16)}` : null);
        addClaim('Boot Seed', data.boot_seed);
        addClaim('Nonce', data.nonce);
        addClaim('Cert Reference', data.certification_reference);
        addClaim('VSI', data.vsi);

        // Render SW Components
        const swContainer = document.getElementById('sw-components-container');
        const swList = document.getElementById('sw-components-list');
        swList.innerHTML = '';

        if (data.software_components && data.software_components.length > 0) {
            swContainer.style.display = 'block';
            data.software_components.forEach(comp => {
                const div = document.createElement('div');
                div.className = 'sw-component';
                
                const c = (l, v) => v ? `<div class="claim-item"><div class="claim-label">${l}</div><div class="claim-value">${v}</div></div>` : '';
                
                div.innerHTML = 
                    c('Measurement Type', comp.measurement_type) +
                    c('Measurement Value', comp.measurement_value) +
                    c('Signer ID', comp.signer_id) +
                    c('Version', comp.version) +
                    c('Description', comp.measurement_desc);
                
                swList.appendChild(div);
            });
        } else {
            swContainer.style.display = 'none';
        }
    };

    fetchBtn.addEventListener('click', async () => {
        fetchBtn.disabled = true;
        resultsSection.classList.add('hidden');
        clearTrail();
        
        // Start forward animation to UART
        await initiateRequest();
        
        const nonceVal = nonceInput ? nonceInput.value.trim() : '';

        // Start API fetch
        const fetchPromise = fetch('/api/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ nonce: nonceVal })
        })
            .then(res => res.json())
            .catch(err => ({ error: err.message }));

        const data = await fetchPromise;

        if (!data.error) {
            // Animate internal flow now that token is here
            await animateChipProcessing();
            await playBackwardAnimation();
        } else {
            nodes.pc.classList.remove('active');
        }

        // Show data
        displayResults(data);
        
        fetchBtn.disabled = false;
    });

    document.addEventListener('keydown', async (e) => {
        if (e.key === 'F' || e.key === 'f') {
            try {
                const res = await fetch('/api/switch-fake', { method: 'POST' });
                const data = await res.json();
                console.log(`Data source toggled to: ${data.state}`);
            } catch (err) {
                console.error('Failed to toggle data source:', err);
            }
        }
    });
});
