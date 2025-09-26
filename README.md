# OPSEC-Check

A tvOS app for performing operational security (OPSEC) checks to verify VPN status, network configuration, and device metadata.

## Features

### Core Security Checks
- **Mullvad VPN Detection**: Verifies if Mullvad VPN is active and shows exit IP, country, and city
- **Public IP Verification**: Checks public IP address and compares with VPN exit IP
- **Device Metadata**: Collects device name, model, tvOS version, locale, and region information
- **Local Network Analysis**: Enumerates all network interfaces and their IP addresses
- **DNS Resolution Test**: Verifies DNS functionality and detects potential leaks

### User Interface
- **Status Summary**: Color-coded PASS/WARNING/FAIL status with overall security assessment
- **Collapsible Sections**: Detailed results for each check category
- **Real-time Updates**: Manual refresh with latency measurements
- **Export Functionality**: Generate and export security reports (opt-in)

### Privacy & Security
- **Local-Only Operation**: No data transmission to third-party servers
- **Encrypted Storage**: Check history stored locally with Keychain-backed encryption
- **No Telemetry**: No analytics, crash reporting, or remote configuration
- **Configurable Endpoints**: Customizable network check endpoints

## Requirements

- tvOS 15.0+
- Xcode 14.0+
- Swift 5.7+

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Qrutz/opsec.git
cd opsec
```

2. Open the project in Xcode:
```bash
open fadsf.xcodeproj
```

3. Build and run on tvOS Simulator or device

## Usage

1. **Run Security Checks**: Use the "Run Checks" button to perform all OPSEC checks
2. **View Results**: Expand sections to see detailed information for each check
3. **Export Reports**: Use the export functionality to save security reports
4. **Configure Endpoints**: Access settings to modify network check endpoints

## Architecture

### Core Components

- **`OPSECCheckService`**: Main service handling all security checks
- **`OPSEChistoryManager`**: Manages local storage of check results
- **`ContentView`**: Main UI with collapsible sections and status display
- **`SettingsView`**: Configuration interface for endpoints and export

### Data Models

- **`OPSEChResult`**: Complete result structure for all checks
- **`MullvadCheckResult`**: VPN detection and exit node information
- **`PublicIPCheckResult`**: Public IP verification results
- **`DNSCheckResult`**: DNS resolution test results
- **`DeviceMetadata`**: Device and system information
- **`NetworkInterface`**: Local network interface details

## Network Endpoints

The app uses the following public endpoints for security checks:

- **Mullvad Check**: `https://am.i.mullvad.net/json`
- **Public IP Check**: `https://api.ipify.org?format=json`
- **Alternative Endpoints**: 
  - `https://httpbin.org/ip`
  - `https://ipapi.co/json/`
  - `https://api.my-ip.io/ip.json`

All endpoints are configurable through the settings interface.

## Security Considerations

- **No Credentials**: No API keys, passwords, or sensitive data stored
- **Local Encryption**: Uses Keychain Services for secure local storage
- **Network Timeouts**: 10-second timeout for all network requests
- **Fallback Mechanisms**: Local network analysis when external endpoints fail
- **Privacy-First**: No data leaves the device unless explicitly exported

## Testing

Run the test suite:
```bash
xcodebuild test -project fadsf.xcodeproj -scheme fadsf -destination 'platform=tvOS Simulator,name=Apple TV 4K (3rd generation)'
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is open source. Please add your preferred license here.

## Disclaimer

This tool is for educational and security assessment purposes. Always ensure you have proper authorization before performing security checks on networks you don't own or manage.
