document.addEventListener('DOMContentLoaded', () => {
    const fetchBtn = document.getElementById('fetch-btn');
    const statusText = document.getElementById('status-text');
    const resultsSection = document.getElementById('results-section');
    
    const nodes = {
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
    const diagram = document.getElementById('arch-diagram');
    let trailConnections = [];

    const getCenter = (node) => {
        const rect = node.getBoundingClientRect();
        const diagRect = diagram.getBoundingClientRect();
        return {
            x: rect.left - diagRect.left + rect.width / 2,
            y: rect.top - diagRect.top + rect.height / 2
        };
    };

    const drawLine = (node1, node2, isBack = false) => {
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
        line.setAttribute('stroke-dasharray', '8 8');
        line.classList.add('trail-line');
        line.style.animation = 'dashAnim 1s linear infinite';
        
        svg.appendChild(line);
    };

    const redrawTrail = () => {
        svg.innerHTML = '';
        trailConnections.forEach(pair => {
            drawLine(pair[0], pair[1], pair[2]);
        });
    };

    window.addEventListener('resize', redrawTrail);

    const addTrailSegment = (n1, n2, isBack = false) => {
        trailConnections.push([n1, n2, isBack]);
        drawLine(n1, n2, isBack);
        n1.classList.add('trail');
        n2.classList.add('trail');
    };

    const clearTrail = () => {
        svg.innerHTML = '';
        trailConnections = [];
        Object.values(nodes).forEach(n => n.classList.remove('trail'));
    };

    const playForwardAnimation = async () => {
        await activateNode(nodes.app, "Tock App requesting token...");
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
        await activateNode(nodes.app, "Tock App received token!");
        await sleep(800);
        deactivateNode(nodes.app);
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
        
        // Start forward animation
        const animPromise = playForwardAnimation();
        
        // Start API fetch
        const fetchPromise = fetch('/api/token', { method: 'POST' })
            .then(res => res.json())
            .catch(err => ({ error: err.message }));

        // Wait for forward animation to complete
        await animPromise;
        
        // Wait for API response if it hasn't finished yet
        statusText.innerText = "Waiting for device response...";
        const data = await fetchPromise;

        // Play backward animation with the returned token
        await playBackwardAnimation();

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
