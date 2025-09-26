//
//  OPSECCheckService.swift
//  fadsf
//
//  Created by Johan Sandgren on 2025-09-26.
//

import Foundation
import Network
import SystemConfiguration

// MARK: - Data Models

struct MullvadResponse: Codable {
    let ip: String
    let country: String
    let city: String
    let isMullvad: Bool
    
    enum CodingKeys: String, CodingKey {
        case ip
        case country
        case city
        case isMullvad = "mullvad_exit_ip"
    }
}

struct IPifyResponse: Codable {
    let ip: String
}

struct HTTPBinResponse: Codable {
    let origin: String
}

struct DeviceMetadata: Codable {
    let deviceName: String
    let modelIdentifier: String
    let osVersion: String
    let locale: String
    let region: String
    let language: String
    let identifierForVendor: String
}

struct NetworkInterface: Codable {
    let name: String
    let ipv4Address: String?
    let ipv6Address: String?
    let isLoopback: Bool
}

struct OPSEChResult {
    let timestamp: Date
    let overallStatus: OPSECStatus
    let mullvadCheck: MullvadCheckResult
    let publicIPCheck: PublicIPCheckResult
    let deviceMetadata: DeviceMetadata
    let localNetwork: [NetworkInterface]
    let dnsCheck: DNSCheckResult
    let latency: TimeInterval
}

enum OPSECStatus: Codable {
    case pass
    case warning
    case fail
    
    var color: String {
        switch self {
        case .pass: return "green"
        case .warning: return "yellow"
        case .fail: return "red"
        }
    }
    
    var displayName: String {
        switch self {
        case .pass: return "PASS"
        case .warning: return "WARNING"
        case .fail: return "FAIL"
        }
    }
}

struct MullvadCheckResult: Codable {
    let isDetected: Bool
    let exitIP: String
    let country: String
    let city: String
    let error: String?
    let latency: TimeInterval
}

struct PublicIPCheckResult: Codable {
    let ip: String
    let error: String?
    let latency: TimeInterval
}

struct DNSCheckResult: Codable {
    let isResolvingCorrectly: Bool
    let error: String?
    let latency: TimeInterval
}

// MARK: - OPSEC Check Service

@MainActor
class OPSECCheckService: ObservableObject {
    @Published var isRunning = false
    @Published var lastResult: OPSEChResult?
    @Published var error: String?
    
    private let session: URLSession
    private let timeout: TimeInterval = 10.0
    private let historyManager = OPSEChistoryManager()
    
    // Configurable endpoints
    var mullvadEndpoint = "https://am.i.mullvad.net/json"
    var ipifyEndpoint = "https://api.ipify.org?format=json"
    
    // Alternative endpoints for testing
    private let alternativeEndpoints = [
        "https://httpbin.org/ip",
        "https://ipapi.co/json/",
        "https://api.my-ip.io/ip.json"
    ]
    
    init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout
        config.waitsForConnectivity = true
        config.allowsCellularAccess = true
        config.httpShouldUsePipelining = false
        config.httpMaximumConnectionsPerHost = 1
        self.session = URLSession(configuration: config)
    }
    
    func runAllChecks() async {
        isRunning = true
        error = nil
        
        let startTime = Date()
        
        // Run checks in parallel
        async let mullvadResult = checkMullvad()
        async let publicIPResult = checkPublicIP()
        async let dnsResult = checkDNS()
        
        let deviceMetadata = getDeviceMetadata()
        let localNetwork = getLocalNetworkInterfaces()
        
        let results = await (mullvadResult, publicIPResult, dnsResult)
        let totalLatency = Date().timeIntervalSince(startTime)
        
        // Determine overall status
        let overallStatus = determineOverallStatus(
            mullvad: results.0,
            publicIP: results.1,
            dns: results.2
        )
        
        let result = OPSEChResult(
            timestamp: Date(),
            overallStatus: overallStatus,
            mullvadCheck: results.0,
            publicIPCheck: results.1,
            deviceMetadata: deviceMetadata,
            localNetwork: localNetwork,
            dnsCheck: results.2,
            latency: totalLatency
        )
        
        lastResult = result
        historyManager.addResult(result)
        
        isRunning = false
    }
    
    private func checkMullvad() async -> MullvadCheckResult {
        let startTime = Date()
        
        do {
            guard let url = URL(string: mullvadEndpoint) else {
                throw URLError(.badURL)
            }
            
            let (data, _) = try await session.data(from: url)
            let responseObj = try JSONDecoder().decode(MullvadResponse.self, from: data)
            let latency = Date().timeIntervalSince(startTime)
            
            return MullvadCheckResult(
                isDetected: responseObj.isMullvad,
                exitIP: responseObj.ip,
                country: responseObj.country,
                city: responseObj.city,
                error: nil,
                latency: latency
            )
            
        } catch {
            let latency = Date().timeIntervalSince(startTime)
            return MullvadCheckResult(
                isDetected: false,
                exitIP: "",
                country: "",
                city: "",
                error: error.localizedDescription,
                latency: latency
            )
        }
    }
    
    private func checkPublicIP() async -> PublicIPCheckResult {
        let startTime = Date()
        
        // Try primary endpoint first
        do {
            guard let url = URL(string: ipifyEndpoint) else {
                throw URLError(.badURL)
            }
            
            let (data, _) = try await session.data(from: url)
            let responseObj = try JSONDecoder().decode(IPifyResponse.self, from: data)
            let latency = Date().timeIntervalSince(startTime)
            
            return PublicIPCheckResult(
                ip: responseObj.ip,
                error: nil,
                latency: latency
            )
            
        } catch {
            print("🔍 IPify: Primary endpoint failed - \(error.localizedDescription)")
            
            // Try alternative endpoints
            for endpoint in alternativeEndpoints {
                do {
                    guard let url = URL(string: endpoint) else { continue }
                    
                    let (data, _) = try await session.data(from: url)
                    
                    // Try to parse as IPifyResponse first
                    if let responseObj = try? JSONDecoder().decode(IPifyResponse.self, from: data) {
                        let latency = Date().timeIntervalSince(startTime)
                        return PublicIPCheckResult(
                            ip: responseObj.ip,
                            error: nil,
                            latency: latency
                        )
                    }
                    
                    // Try to parse as HTTPBin response
                    if let httpbinResponse = try? JSONDecoder().decode(HTTPBinResponse.self, from: data) {
                        let latency = Date().timeIntervalSince(startTime)
                        return PublicIPCheckResult(
                            ip: httpbinResponse.origin,
                            error: nil,
                            latency: latency
                        )
                    }
                    
                } catch {
                    continue
                }
            }
            
            // If all external endpoints fail, try to get local network info as fallback
            let localInterfaces = getLocalNetworkInterfaces()
            let publicIPs = localInterfaces.compactMap { interface in
                // Look for non-loopback, non-link-local addresses that might be public
                if !interface.isLoopback {
                    return interface.ipv4Address ?? interface.ipv6Address
                }
                return nil
            }.filter { ip in
                // Filter out private IP ranges
                !ip.hasPrefix("192.168.") && !ip.hasPrefix("10.") && !ip.hasPrefix("172.")
            }
            
            let latency = Date().timeIntervalSince(startTime)
            
            if let fallbackIP = publicIPs.first {
                return PublicIPCheckResult(
                    ip: fallbackIP,
                    error: "External endpoints failed, using local network IP",
                    latency: latency
                )
            }
            return PublicIPCheckResult(
                ip: "",
                error: "All IP endpoints failed: \(error.localizedDescription)",
                latency: latency
            )
        }
    }
    
    private func checkDNS() async -> DNSCheckResult {
        let startTime = Date()
        
        // Try multiple DNS test endpoints
        let dnsTestURLs = [
            "https://httpbin.org/ip",
            "https://api.ipify.org?format=json",
            "https://am.i.mullvad.net/json"
        ]
        
        for dnsTestURL in dnsTestURLs {
            do {
                guard let url = URL(string: dnsTestURL) else {
                    continue
                }
                
                let (data, _) = try await session.data(from: url)
                let latency = Date().timeIntervalSince(startTime)
                
                return DNSCheckResult(
                    isResolvingCorrectly: true,
                    error: nil,
                    latency: latency
                )
                
            } catch {
                continue
            }
        }
        
        // If all external DNS tests fail, check if we have any network connectivity at all
        let localInterfaces = getLocalNetworkInterfaces()
        let hasNetworkInterfaces = localInterfaces.contains { !$0.isLoopback }
        
        let latency = Date().timeIntervalSince(startTime)
        
        if hasNetworkInterfaces {
            return DNSCheckResult(
                isResolvingCorrectly: false,
                error: "External DNS resolution failed, but local network detected",
                latency: latency
            )
        } else {
            return DNSCheckResult(
                isResolvingCorrectly: false,
                error: "No network connectivity detected",
                latency: latency
            )
        }
    }
    
    private func getDeviceMetadata() -> DeviceMetadata {
        let locale = Locale.current
        
        return DeviceMetadata(
            deviceName: getDeviceName(),
            modelIdentifier: getModelIdentifier(),
            osVersion: "tvOS \(ProcessInfo.processInfo.operatingSystemVersionString)",
            locale: locale.identifier,
            region: locale.region?.identifier ?? "Unknown",
            language: locale.language.languageCode?.identifier ?? "Unknown",
            identifierForVendor: getIdentifierForVendor()
        )
    }
    
    private func getDeviceName() -> String {
        // For tvOS, use hostname as the device name
        let hostname = ProcessInfo.processInfo.hostName
        
        // Extract the first part before any dots
        if let deviceName = hostname.components(separatedBy: ".").first, !deviceName.isEmpty {
            return deviceName
        }
        
        // Fallback to a more descriptive name based on model
        let model = getModelIdentifier()
        if model.contains("AppleTV") {
            return "Apple TV"
        }
        
        // Final fallback
        return "tvOS Device"
    }
    
    private func getModelIdentifier() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let modelCode = withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                ptr in String.init(validatingUTF8: ptr)
            }
        }
        return modelCode ?? "Unknown"
    }
    
    private func getIdentifierForVendor() -> String {
        // For tvOS, we can use a combination of model and system info
        let model = getModelIdentifier()
        let systemInfo = ProcessInfo.processInfo
        let hostname = systemInfo.hostName
        
        // Create a pseudo-IDFV based on device characteristics
        let combined = "\(model)-\(hostname)"
        return String(combined.hash)
    }
    
    private func getLocalNetworkInterfaces() -> [NetworkInterface] {
        var interfaces: [NetworkInterface] = []
        
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return interfaces }
        guard let firstAddr = ifaddr else { return interfaces }
        
        for ifptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let interface = ifptr.pointee
            
            let name = String(cString: interface.ifa_name)
            let addr = interface.ifa_addr.pointee
            
            var ipv4Address: String?
            var ipv6Address: String?
            let isLoopback = (interface.ifa_flags & UInt32(IFF_LOOPBACK)) != 0
            
            if addr.sa_family == UInt8(AF_INET) {
                var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                getnameinfo(interface.ifa_addr, socklen_t(addr.sa_len), &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST)
                ipv4Address = String(cString: hostname)
            } else if addr.sa_family == UInt8(AF_INET6) {
                var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                getnameinfo(interface.ifa_addr, socklen_t(addr.sa_len), &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST)
                ipv6Address = String(cString: hostname)
            }
            
            interfaces.append(NetworkInterface(
                name: name,
                ipv4Address: ipv4Address,
                ipv6Address: ipv6Address,
                isLoopback: isLoopback
            ))
        }
        
        freeifaddrs(ifaddr)
        return interfaces
    }
    
    private func determineOverallStatus(
        mullvad: MullvadCheckResult,
        publicIP: PublicIPCheckResult,
        dns: DNSCheckResult
    ) -> OPSECStatus {
        // Check for critical failures - but be more lenient with network issues
        let hasNetworkIssues = publicIP.error?.contains("External endpoints failed") == true || 
                              dns.error?.contains("External") == true
        
        if mullvad.error != nil {
            return .fail
        }
        
        // If we have network issues but Mullvad check worked, it's a warning
        if hasNetworkIssues && !mullvad.exitIP.isEmpty {
            return .warning
        }
        
        // If we have no network connectivity at all, it's a fail
        if publicIP.error?.contains("All IP endpoints failed") == true && 
           dns.error?.contains("No network connectivity") == true {
            return .fail
        }
        
        // Check if Mullvad is detected and IPs match
        if mullvad.isDetected && mullvad.exitIP == publicIP.ip {
            return .pass
        }
        
        // Check for potential issues
        if !mullvad.isDetected && mullvad.exitIP != publicIP.ip {
            return .warning
        }
        
        return .fail
    }
    
    func exportReport() -> String {
        guard let result = lastResult else { return "No results available" }
        
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        
        var report = """
        OPSEC Check Report
        Generated: \(formatter.string(from: result.timestamp))
        Overall Status: \(result.overallStatus.displayName)
        Total Latency: \(String(format: "%.2f", result.latency))s
        
        === MULLVAD CHECK ===
        Detected: \(result.mullvadCheck.isDetected ? "Yes" : "No")
        Exit IP: \(result.mullvadCheck.exitIP)
        Country: \(result.mullvadCheck.country)
        City: \(result.mullvadCheck.city)
        Latency: \(String(format: "%.2f", result.mullvadCheck.latency))s
        Error: \(result.mullvadCheck.error ?? "None")
        
        === PUBLIC IP CHECK ===
        IP: \(result.publicIPCheck.ip)
        Latency: \(String(format: "%.2f", result.publicIPCheck.latency))s
        Error: \(result.publicIPCheck.error ?? "None")
        
        === DEVICE METADATA ===
        Device Name: \(result.deviceMetadata.deviceName)
        Model: \(result.deviceMetadata.modelIdentifier)
        OS Version: \(result.deviceMetadata.osVersion)
        Locale: \(result.deviceMetadata.locale)
        Region: \(result.deviceMetadata.region)
        Language: \(result.deviceMetadata.language)
        IDFV: \(result.deviceMetadata.identifierForVendor)
        
        === LOCAL NETWORK ===
        """
        
        for interface in result.localNetwork {
            report += "\n\(interface.name):"
            if let ipv4 = interface.ipv4Address {
                report += "\n  IPv4: \(ipv4)"
            }
            if let ipv6 = interface.ipv6Address {
                report += "\n  IPv6: \(ipv6)"
            }
            if interface.isLoopback {
                report += " (Loopback)"
            }
        }
        
        report += """
        
        === DNS CHECK ===
        Resolving Correctly: \(result.dnsCheck.isResolvingCorrectly ? "Yes" : "No")
        Latency: \(String(format: "%.2f", result.dnsCheck.latency))s
        Error: \(result.dnsCheck.error ?? "None")
        """
        
        return report
    }
}
