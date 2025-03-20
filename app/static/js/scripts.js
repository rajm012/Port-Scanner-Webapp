// Show/hide sections dynamically
function showSection(sectionId) {
    document.getElementById(sectionId).classList.remove('hidden');
}

function hideSection(sectionId) {
    document.getElementById(sectionId).classList.add('hidden');
}

// Clear all results
document.getElementById('clear-results').addEventListener('click', function () {
    document.getElementById('results').innerHTML = '<h2>Scan Results</h2><div id="all-results"></div>';
    hideSection('results');

    document.getElementById('additional-results').innerHTML = '<h2>Additional Results</h2><div id="shodan-results"></div><div id="geoip-results"></div><div id="os-results"></div>';
    hideSection('additional-results');
});

// Function to format and display Additional Results
function displayAdditionalResults(data, resultContainerId) {
    const resultDiv = document.getElementById(resultContainerId);
    resultDiv.innerHTML = ''; // Clear previous results

    if (!data) {
        resultDiv.innerHTML = `<p class="error">⚠️ No data available.</p>`;
        return;
    }

    let formattedHtml = `<div class="result-card">`;

    if (data.IP) {
        formattedHtml += `
            <h3>🌐 IP & ISP Information</h3>
            <p><strong>IP:</strong> ${data.IP}</p>
            <p><strong>ISP:</strong> ${data.ISP || 'N/A'}</p>
            <p><strong>Organization:</strong> ${data.Organization || 'N/A'}</p>
        `;
    }

    if (data["Open Ports"] && data["Open Ports"].length > 0) {
        formattedHtml += `
            <h3>🚪 Open Ports</h3>
            <p>${data["Open Ports"].map(port => `<span class="port">${port}</span>`).join(' ')}</p>
        `;
    }

    if (data.City && data.Country) {
        formattedHtml += `
            <h3>📍 Geolocation</h3>
            <p><strong>City:</strong> ${data.City}</p>
            <p><strong>Region:</strong> ${data.Region || 'N/A'}</p>
            <p><strong>Country:</strong> ${data.Country}</p>
        `;
    }

    if (data.os) {
        formattedHtml += `
            <h3>💻 OS Detection</h3>
            <p><strong>Detected OS:</strong> ${data.os}</p>
            <p><strong>TTL Value:</strong> ${data.ttl}</p>
        `;
    }

    if (data.Vulnerabilities) {
        formattedHtml += `
            <h3>⚠️ Vulnerabilities</h3>
            <p>${data.Vulnerabilities}</p>
        `;
    }

    formattedHtml += `</div>`;
    resultDiv.innerHTML = formattedHtml;

    // Show the additional results section
    showSection('additional-results');
}

// Scan Form Submission
document.getElementById('scan-form').addEventListener('submit', function (event) {
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
            resultsDiv.innerHTML = '<h2>Scan Results</h2><div id="all-results"></div>';

            const allResults = document.getElementById('all-results');
            data.forEach(result => {
                const row = document.createElement('div');
                row.className = result.status.toLowerCase();
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
document.getElementById('shodan-lookup').addEventListener('click', function () {
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
            displayAdditionalResults(data, 'shodan-results');
        });
});

// GeoIP Lookup
document.getElementById('geoip-lookup').addEventListener('click', function () {
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
            displayAdditionalResults(data, 'geoip-results');
        });
});

// OS Detection
document.getElementById('os-detection').addEventListener('click', function () {
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
            displayAdditionalResults(data, 'os-results');
        });
});


document.getElementById("scan-form").addEventListener("submit", function(event) {
    event.preventDefault();

    // Show results section when scanning starts
    document.getElementById("results").classList.remove("hidden");
    document.getElementById("scan-results").innerHTML = "<p>🔍 Scanning in progress...</p>";

    // Simulating Scan Results (Replace with actual API call)
    setTimeout(() => {
        let results = "Port 22: Open\nPort 80: Open\nPort 443: Open\nPort 8080: Closed";
        document.getElementById("scan-results").innerText = results;

        // Show download button
        let downloadBtn = document.getElementById("download-results");
        downloadBtn.classList.remove("hidden");
        downloadBtn.style.display = "inline-block"; // Ensures visibility
    }, 2000); // Simulating 2 sec delay
});

// Download Scan Results
document.getElementById("download-results").addEventListener("click", function() {
    let scanResults = document.getElementById("scan-results").innerText;
    let blob = new Blob([scanResults], { type: "text/plain" });
    let link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "scan_results.txt";
    link.click();
});

// Clear Results Functionality
document.getElementById("clear-results").addEventListener("click", function() {
    document.getElementById("scan-results").innerHTML = "";
    document.getElementById("results").classList.add("hidden");
    document.getElementById("download-results").classList.add("hidden");
});

