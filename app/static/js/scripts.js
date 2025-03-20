document.getElementById('scan-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const formData = new FormData(this);
    fetch('/scan', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        const resultsDiv = document.getElementById('results');
        resultsDiv.innerHTML = '<h2>Scan Results</h2>';
        if (data.error) {
            resultsDiv.innerHTML += `<p class="error">${data.error}</p>`;
        } else {
            const table = document.createElement('table');
            const thead = document.createElement('thead');
            const tbody = document.createElement('tbody');
            thead.innerHTML = '<tr><th>Port</th><th>Status</th><th>Service</th></tr>';
            data.forEach(result => {
                const row = document.createElement('tr');
                row.innerHTML = `<td>${result.port}</td><td>${result.status}</td><td>${result.service}</td>`;
                tbody.appendChild(row);
            });
            table.appendChild(thead);
            table.appendChild(tbody);
            resultsDiv.appendChild(table);
        }
    });
});


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
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { throw new Error(err.error); });
        }
        return response.json();
    })
    .then(data => {
        alert(JSON.stringify(data, null, 2));
    })
    .catch(error => {
        alert(`Error: ${error.message}`);
    });
});

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
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { throw new Error(err.error); });
        }
        return response.json();
    })
    .then(data => {
        alert(JSON.stringify(data, null, 2));
    })
    .catch(error => {
        alert(`Error: ${error.message}`);
    });
});


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
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { throw new Error(err.error); });
        }
        return response.json();
    })
    .then(data => {
        alert(JSON.stringify(data, null, 2));
    })
    .catch(error => {
        alert(`Error: ${error.message}`);
    });
});