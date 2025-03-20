document.addEventListener('DOMContentLoaded', function () {
    console.log("DOM fully loaded and parsed."); // Debugging step

    // Show/hide sections dynamically
    function showSection(sectionId) {
        const section = document.getElementById(sectionId);
        if (section) {
            section.classList.remove('hidden');
        } else {
            console.error(`Section not found: ${sectionId}`);
        }
    }

    function hideSection(sectionId) {
        const section = document.getElementById(sectionId);
        if (section) {
            section.classList.add('hidden');
        } else {
            console.error(`Section not found: ${sectionId}`);
        }
    }

    // Clear all results
    document.getElementById('clear-results').addEventListener('click', function () {
        document.getElementById('all-results').innerHTML = '';
        hideSection('results');
        hideSection('additional-results');
    });

    // Show the Download Button when scan results are available
    function showDownloadButton() {
        const downloadButton = document.getElementById('download-results');
        if (downloadButton) {
            downloadButton.classList.remove('hidden');
        } else {
            console.error('Download button not found!');
        }
    }

    // Handle Download Results Button Click
    const downloadButton = document.getElementById('download-results');
    if (downloadButton) {
        downloadButton.addEventListener('click', function () {
            fetch('/download_results')
                .then(response => {
                    if (!response.ok) {
                        throw new Error("Failed to fetch scan results.");
                    }
                    return response.blob();
                })
                .then(blob => {
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'scan_results.json';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                })
                .catch(error => {
                    console.error("Error downloading results:", error);
                    alert("Failed to download results. Please check the console for details.");
                });
        });
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
                const allResults = document.getElementById('all-results');
                allResults.innerHTML = '';

                data.forEach(result => {
                    const row = document.createElement('div');
                    row.className = `result-row ${result.status.toLowerCase()}`;
                    row.innerHTML = `
                        <span class="port">Port: ${result.port}</span>
                        <span class="status">Status: ${result.status}</span>
                        <span class="service">Service: ${result.service}</span>
                    `;
                    allResults.appendChild(row);
                });

                // Show the download button after scan completes
                showDownloadButton();
            })
            .catch(error => {
                console.error("Error during scan:", error);
            });
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

        // IP & ISP Information
        if (data.IP) {
            formattedHtml += `
                <div class="info-section">
                    <h3>🌐 IP & ISP Information</h3>
                    <p><strong>IP:</strong> ${data.IP}</p>
                    <p><strong>ISP:</strong> ${data.ISP || 'N/A'}</p>
                    <p><strong>Organization:</strong> ${data.Organization || 'N/A'}</p>
                </div>
            `;
        }

        // Open Ports
        if (data["Open Ports"] && data["Open Ports"].length > 0) {
            formattedHtml += `
                <div class="info-section">
                    <h3>🚪 Open Ports</h3>
                    <div class="port-list">
                        ${data["Open Ports"].map(port => `<span class="port">${port}</span>`).join(' ')}
                    </div>
                </div>
            `;
        }

        // Geolocation
        if (data.City && data.Country) {
            formattedHtml += `
                <div class="info-section">
                    <h3>📍 Geolocation</h3>
                    <p><strong>City:</strong> ${data.City}</p>
                    <p><strong>Region:</strong> ${data.Region || 'N/A'}</p>
                    <p><strong>Country:</strong> ${data.Country}</p>
                </div>
            `;
        }

        // OS Detection
        if (data.os) {
            formattedHtml += `
                <div class="info-section">
                    <h3>💻 OS Detection</h3>
                    <p><strong>Detected OS:</strong> ${data.os}</p>
                    <p><strong>TTL Value:</strong> ${data.ttl}</p>
                </div>
            `;
        }

        // Vulnerabilities
        if (data.Vulnerabilities) {
            formattedHtml += `
                <div class="info-section">
                    <h3>⚠️ Vulnerabilities</h3>
                    <p>${data.Vulnerabilities}</p>
                </div>
            `;
        }

        formattedHtml += `</div>`;
        resultDiv.innerHTML = formattedHtml;

        // Show the additional results section
        showSection('additional-results');
    }

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
            })
            .catch(error => {
                console.error("Error during Shodan lookup:", error);
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
            })
            .catch(error => {
                console.error("Error during GeoIP lookup:", error);
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
            })
            .catch(error => {
                console.error("Error during OS detection:", error);
            });
    });
});