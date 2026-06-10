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

    const playForwardAnimation = async () => {
        await activateNode(nodes.app, "Tock App requesting token...");
        deactivateNode(nodes.app);

        await activateNode(nodes.kernel, "Kernel routing request to SPE...");
        deactivateNode(nodes.kernel);

        await activateNode(nodes.spe, "SPE delegating to Attestation Service...");
        deactivateNode(nodes.spe);

        await activateNode(nodes.attest, "Attestation Service gathering claims...");
        deactivateNode(nodes.attest);

        await activateNode(nodes.crypto, "Crypto Service signing the token...");
        await sleep(400); // Simulating crypto work
    };

    const playBackwardAnimation = async () => {
        statusText.innerText = "Signature generated, returning token...";
        deactivateNode(nodes.crypto);

        await activateNode(nodes.attest, "Attestation Service assembling token...");
        deactivateNode(nodes.attest);

        await activateNode(nodes.spe, "SPE returning token to Kernel...");
        deactivateNode(nodes.spe);

        await activateNode(nodes.kernel, "Kernel passing token to User Space...");
        deactivateNode(nodes.kernel);

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
});
