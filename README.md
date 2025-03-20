
# 🔍 Basic Port Scanner(WebApp)

The **Basic Port Scanner** is a powerful web-based tool designed to scan ports on a target IP address. It provides detailed information about open ports, services, and additional data such as geolocation, operating system detection, and Shodan lookup results. Built with **Flask** for the backend and **HTML/CSS/JavaScript** for the frontend, this tool is perfect for network administrators, security professionals, and enthusiasts.

---

## 🚀 Features

- **Port Scanning**:
  - Scan a range of ports on a target IP address using **TCP**, **UDP**, or **SYN** scan methods.
  - View detailed results, including port number, status (open/closed), and service running on the port.

- **Shodan Lookup**:
  - Retrieve additional information about the target IP using **Shodan**, including open ports, organization, ISP, and vulnerabilities.

- **GeoIP Lookup**:
  - Get geolocation data for the target IP, including city, region, country, and ISP.

- **OS Detection**:
  - Detect the operating system of the target IP based on **TTL (Time to Live)** values.

- **Download Results**:
  - Download the scan results as a **JSON file** for further analysis.

- **User-Friendly Interface**:
  - Clean and intuitive design with a floating **Help** button for quick access to documentation.

---

## 🛠️ Technologies Used

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **APIs**: Shodan, GeoIP
- **Styling**: Custom CSS with responsive design

---

## 🚀 Getting Started

### Prerequisites

- Python 3.x
- Flask
- Shodan API Key (optional, for Shodan lookup)
- GeoIP API (optional, for GeoIP lookup)

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/rajm012/Port-Scanner-Webapp.git
   cd Port-Scanner-Webapp
   ```

2. **Set Up a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set Up Environment Variables**:
   Create a `.env` file in the root directory and add your Shodan API key (if applicable):
   ```env
   SHODAN_API_KEY=your_shodan_api_key
   ```

5. **Run the Application**:
   ```bash
   python app.py
   ```

6. **Access the Web App**:
   Open your browser and navigate to `http://127.0.0.1:5000`.

---

## 🖥️ Usage

1. **Enter Target IP**:
   - Enter the target IP address in the "Target IP" field.

2. **Specify Port Range**:
   - Set the start and end port range for the scan.

3. **Select Scan Type**:
   - Choose the scan type: **TCP**, **UDP**, or **SYN**.

4. **Start Scan**:
   - Click **🚀 Start Scan** to begin the scan.

5. **View Results**:
   - The scan results will be displayed in the "Scan Results" section.

6. **Use Additional Tools**:
   - Use the **Shodan Lookup**, **GeoIP Lookup**, and **OS Detection** tools for more information.

7. **Download Results**:
   - Click **📥 Download Results** to save the scan results as a JSON file.

---

## 📂 Project Structure

```
advanced-port-scanner/
├── app.py                  # Flask application
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables
├── templates/              # HTML templates
│   ├── index.html          # Main page
│   └── help.html           # Help page
├── static/                 # Static files
│   ├── css/                # CSS files
│   │   └── styles.css      # Main stylesheet
│   └── js/                 # JavaScript files
│       └── scripts.js      # Main JavaScript file
├── scanner.py              # Port scanning logic
└── README.md               # Project documentation
```

---

## 📜 Help

For detailed information about the features and usage of the Advanced Port Scanner, click the **❓ Help** button on the main page or visit the [Help Page](http://127.0.0.1:5000/help).

---

## 🤝 Contributing

Contributions are welcome! If you'd like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature-name`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/your-feature-name`).
5. Open a pull request.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Flask](https://flask.palletsprojects.com/) for the web framework.
- [Shodan](https://www.shodan.io/) for the IP lookup API.
- [GeoIP](https://ipinfo.io/) for geolocation data.

---

## 📧 Contact

For questions or feedback, please contact:
- **Email**: syntaxajju@gmail.com
- **GitHub**: [rajm012](https://github.com/rajm012)

---

Happy Scanning! 🎉
