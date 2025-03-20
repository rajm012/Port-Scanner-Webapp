// Show/hide sections dynamically
function showSection(sectionId) {
    const section = document.getElementById(sectionId);
    section.classList.remove('hidden');
}

function hideSection(sectionId) {
    const section = document.getElementById(sectionId);
    section.classList.add('hidden');
}

// Clear all results
document.getElementById('clear-results').addEventListener('click', function() {
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = '<h2>Scan Results</h2><div id="open-unknown-results"></div><div id="closed-results"><h3>Closed Ports</h3></div>';
    hideSection('results');

    const additionalResultsDiv = document.getElementById('additional-results');
    additionalResultsDiv.innerHTML = '<h2>Additional Results</h2><div id="shodan-results"></div><div id="geoip-results"></div><div id="os-results"></div>';
    hideSection('additional-results');
});


document.getElementById('scan-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const formData = new FormData(this);
    const scanType = document.querySelector('input[name="scan_type"]:checked').value;
    formData.append('scan_type', scanType);

    fetch('/scan', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        showSection('results');
        const resultsDiv = document.getElementById('results');
        resultsDiv.innerHTML = '<h2>Scan Results</h2><div id="all-results" style="max-height: 300px; overflow-y: auto;"></div>';

        const allResults = document.getElementById('all-results');
        data.forEach(result => {
            const row = document.createElement('div');
            if (result.status === "Open") {
                row.className = "open";
            } else if (result.status === "Filtered") {
                row.className = "filtered";
            } else if (result.status === "Closed") {
                row.className = "closed";
            } else if (result.status === "Error") {
                row.className = "error";
            }
            row.innerHTML = `Port: ${result.port}, Status: ${result.status}, Service: ${result.service}`;
            allResults.appendChild(row);
        });
    })
    .catch(error => {
        alert("An error occurred. Please check the console for details.");
        console.error(error);
    });
});


// Shodan Lookup
document.getElementById('shodan-lookup').addEventListener('click', function() {
    const targetIp = document.getElementById('target_ip').value;
    if (!targetIp) {
        alert("Please enter a target IP address.");
        return;
    }

    fetch('/shodan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target_ip: targetIp })
    })
    .then(response => response.json())
    .then(data => {
        showSection('additional-results');
        const shodanResults = document.getElementById('shodan-results');
        shodanResults.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    });
});

// GeoIP Lookup
document.getElementById('geoip-lookup').addEventListener('click', function() {
    const targetIp = document.getElementById('target_ip').value;
    if (!targetIp) {
        alert("Please enter a target IP address.");
        return;
    }

    fetch('/geoip', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target_ip: targetIp })
    })
    .then(response => response.json())
    .then(data => {
        showSection('additional-results');
        const geoipResults = document.getElementById('geoip-results');
        geoipResults.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    });
});

// OS Detection
document.getElementById('os-detection').addEventListener('click', function() {
    const targetIp = document.getElementById('target_ip').value;
    if (!targetIp) {
        alert("Please enter a target IP address.");
        return;
    }

    fetch('/os_detection', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target_ip: targetIp })
    })
    .then(response => response.json())
    .then(data => {
        showSection('additional-results');
        const osResults = document.getElementById('os-results');
        osResults.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    });
});