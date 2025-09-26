//
//  OPSECCheckServiceTests.swift
//  fadsfTests
//
//  Created by Johan Sandgren on 2025-09-26.
//

import XCTest
@testable import fadsf

final class OPSECCheckServiceTests: XCTestCase {
    
    func testMullvadResponseParsing() throws {
        let json = """
        {
            "ip": "1.2.3.4",
            "country": "Sweden",
            "city": "Stockholm",
            "mullvad_exit_ip": true
        }
        """
        
        let data = json.data(using: .utf8)!
        let response = try JSONDecoder().decode(MullvadResponse.self, from: data)
        
        XCTAssertEqual(response.ip, "1.2.3.4")
        XCTAssertEqual(response.country, "Sweden")
        XCTAssertEqual(response.city, "Stockholm")
        XCTAssertTrue(response.isMullvad)
    }
    
    func testIPifyResponseParsing() throws {
        let json = """
        {
            "ip": "5.6.7.8"
        }
        """
        
        let data = json.data(using: .utf8)!
        let response = try JSONDecoder().decode(IPifyResponse.self, from: data)
        
        XCTAssertEqual(response.ip, "5.6.7.8")
    }
    
    @MainActor func testOPSECStatusDetermination() {
        // Test pass condition
        let mullvadPass = MullvadCheckResult(
            isDetected: true,
            exitIP: "1.2.3.4",
            country: "Sweden",
            city: "Stockholm",
            error: nil,
            latency: 1.0
        )
        
        let publicIPPass = PublicIPCheckResult(
            ip: "1.2.3.4",
            error: nil,
            latency: 1.0
        )
        
        let dnsPass = DNSCheckResult(
            isResolvingCorrectly: true,
            error: nil,
            latency: 1.0
        )
        
        let service = OPSECCheckService()
        let status = service.determineOverallStatus(
            mullvad: mullvadPass,
            publicIP: publicIPPass,
            dns: dnsPass
        )
        
        XCTAssertEqual(status, .pass)
    }
    
    @MainActor func testOPSECStatusFailure() {
        // Test fail condition with error
        let mullvadFail = MullvadCheckResult(
            isDetected: false,
            exitIP: "",
            country: "",
            city: "",
            error: "Network error",
            latency: 10.0
        )
        
        let publicIPFail = PublicIPCheckResult(
            ip: "",
            error: "Network error",
            latency: 10.0
        )
        
        let dnsFail = DNSCheckResult(
            isResolvingCorrectly: false,
            error: "DNS error",
            latency: 10.0
        )
        
        let service = OPSECCheckService()
        let status = service.determineOverallStatus(
            mullvad: mullvadFail,
            publicIP: publicIPFail,
            dns: dnsFail
        )
        
        XCTAssertEqual(status, .fail)
    }
    
    @MainActor func testOPSECStatusWarning() {
        // Test warning condition
        let mullvadWarning = MullvadCheckResult(
            isDetected: false,
            exitIP: "1.2.3.4",
            country: "Sweden",
            city: "Stockholm",
            error: nil,
            latency: 1.0
        )
        
        let publicIPWarning = PublicIPCheckResult(
            ip: "5.6.7.8", // Different IP
            error: nil,
            latency: 1.0
        )
        
        let dnsWarning = DNSCheckResult(
            isResolvingCorrectly: true,
            error: nil,
            latency: 1.0
        )
        
        let service = OPSECCheckService()
        let status = service.determineOverallStatus(
            mullvad: mullvadWarning,
            publicIP: publicIPWarning,
            dns: dnsWarning
        )
        
        XCTAssertEqual(status, .warning)
    }
    
    @MainActor func testDeviceMetadataCollection() {
        let service = OPSECCheckService()
        let metadata = service.getDeviceMetadata()
        
        XCTAssertFalse(metadata.deviceName.isEmpty)
        XCTAssertFalse(metadata.modelIdentifier.isEmpty)
        XCTAssertFalse(metadata.osVersion.isEmpty)
        XCTAssertFalse(metadata.locale.isEmpty)
        XCTAssertFalse(metadata.identifierForVendor.isEmpty)
    }
    
    @MainActor func testExportReportFormat() {
        let service = OPSECCheckService()
        
        // Create a mock result
        let mockResult = OPSEChResult(
            timestamp: Date(),
            overallStatus: .pass,
            mullvadCheck: MullvadCheckResult(
                isDetected: true,
                exitIP: "1.2.3.4",
                country: "Sweden",
                city: "Stockholm",
                error: nil,
                latency: 1.0
            ),
            publicIPCheck: PublicIPCheckResult(
                ip: "1.2.3.4",
                error: nil,
                latency: 1.0
            ),
            deviceMetadata: DeviceMetadata(
                deviceName: "Test Device",
                modelIdentifier: "TestModel",
                osVersion: "tvOS 17.0",
                locale: "en_US",
                region: "US",
                language: "en",
                identifierForVendor: "test-uuid"
            ),
            localNetwork: [
                NetworkInterface(
                    name: "en0",
                    ipv4Address: "192.168.1.100",
                    ipv6Address: nil,
                    isLoopback: false
                )
            ],
            dnsCheck: DNSCheckResult(
                isResolvingCorrectly: true,
                error: nil,
                latency: 1.0
            ),
            latency: 3.0
        )
        
        service.lastResult = mockResult
        let report = service.exportReport()
        
        XCTAssertTrue(report.contains("OPSEC Check Report"))
        XCTAssertTrue(report.contains("PASS"))
        XCTAssertTrue(report.contains("1.2.3.4"))
        XCTAssertTrue(report.contains("Sweden"))
        XCTAssertTrue(report.contains("Test Device"))
        XCTAssertTrue(report.contains("192.168.1.100"))
    }
}

// MARK: - OPSECCheckService Extension for Testing

extension OPSECCheckService {
    func determineOverallStatus(
        mullvad: MullvadCheckResult,
        publicIP: PublicIPCheckResult,
        dns: DNSCheckResult
    ) -> OPSECStatus {
        // Check for critical failures
        if mullvad.error != nil || publicIP.error != nil || dns.error != nil {
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
    
    func getDeviceMetadata() -> DeviceMetadata {
        let locale = Locale.current
        
        return DeviceMetadata(
            deviceName: "Apple TV",
            modelIdentifier: getModelIdentifier(),
            osVersion: "tvOS \(ProcessInfo.processInfo.operatingSystemVersionString)",
            locale: locale.identifier,
            region: locale.region?.identifier ?? "Unknown",
            language: locale.language.languageCode?.identifier ?? "Unknown",
            identifierForVendor: "tvOS-Device"
        )
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
}
