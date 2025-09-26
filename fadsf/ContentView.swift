//
//  ContentView.swift
//  fadsf
//
//  Created by Johan Sandgren on 2025-09-26.
//

import SwiftUI

struct ContentView: View {
    @StateObject private var opsecService = OPSECCheckService()
    @State private var expandedSections: Set<SectionType> = []
    @State private var showingSettings = false
    @State private var showingExportAlert = false
    @State private var exportText = ""
    
    enum SectionType: CaseIterable {
        case mullvad
        case publicIP
        case device
        case localNetwork
        case dns
    }
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    // Header with overall status
                    headerView
                    
                    // Main content sections
                    VStack(spacing: 16) {
                        mullvadSection
                        publicIPSection
                        deviceSection
                        localNetworkSection
                        dnsSection
                    }
                    .padding(.horizontal)
                    
                    // Action buttons
                    actionButtons
                        .padding(.horizontal)
                        .padding(.bottom, 40)
                }
            }
            .navigationTitle("OPSEC Check")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Settings") {
                        showingSettings = true
                    }
                    .accessibilityLabel("Open settings")
                    .accessibilityHint("Configure network endpoints and export options")
                }
            }
        }
        .onAppear {
            Task {
                await opsecService.runAllChecks()
            }
        }
        .sheet(isPresented: $showingSettings) {
            SettingsView(opsecService: opsecService)
        }
        .alert("Export Report", isPresented: $showingExportAlert) {
            Button("Copy to Clipboard") {
                // For tvOS, we'll just show the text in the alert
                // In a real implementation, you might want to use AirPlay or other sharing methods
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text(exportText)
        }
    }
    
    private var headerView: some View {
        VStack(spacing: 12) {
            if let result = opsecService.lastResult {
                Text(result.overallStatus.displayName)
                    .font(.largeTitle)
                    .fontWeight(.bold)
                    .foregroundColor(statusColor(result.overallStatus))
                
                Text("Last check: \(formatTimestamp(result.timestamp))")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                Text("Latency: \(String(format: "%.2f", result.latency))s")
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else if opsecService.isRunning {
                ProgressView("Running checks...")
                    .font(.title2)
            } else {
                Text("Ready to check")
                    .font(.title2)
                    .foregroundColor(.secondary)
            }
            
            if let error = opsecService.error {
                Text("Error: \(error)")
                    .font(.caption)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
            }
        }
        .padding()
        .background(Color.gray.opacity(0.2))
        .cornerRadius(12)
        .padding(.horizontal)
    }
    
    private var mullvadSection: some View {
        CollapsibleSection(
            title: "Mullvad Check",
            isExpanded: expandedSections.contains(.mullvad),
            onToggle: { toggleSection(.mullvad) }
        ) {
            Group {
                if let result = opsecService.lastResult {
                    VStack(alignment: .leading, spacing: 8) {
                        StatusRow(title: "Detected", value: result.mullvadCheck.isDetected ? "Yes" : "No", isGood: result.mullvadCheck.isDetected)
                        StatusRow(title: "Exit IP", value: result.mullvadCheck.exitIP, isGood: !result.mullvadCheck.exitIP.isEmpty)
                        StatusRow(title: "Country", value: result.mullvadCheck.country, isGood: !result.mullvadCheck.country.isEmpty)
                        StatusRow(title: "City", value: result.mullvadCheck.city, isGood: !result.mullvadCheck.city.isEmpty)
                        StatusRow(title: "Latency", value: "\(String(format: "%.2f", result.mullvadCheck.latency))s", isGood: result.mullvadCheck.latency < 2.0)
                        
                        if let error = result.mullvadCheck.error {
                            Text("Error: \(error)")
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                    }
                } else {
                    EmptyView()
                }
            }
        }
    }
    
    private var publicIPSection: some View {
        CollapsibleSection(
            title: "Public IP Check",
            isExpanded: expandedSections.contains(.publicIP),
            onToggle: { toggleSection(.publicIP) }
        ) {
            Group {
                if let result = opsecService.lastResult {
                    VStack(alignment: .leading, spacing: 8) {
                        StatusRow(title: "IP Address", value: result.publicIPCheck.ip, isGood: !result.publicIPCheck.ip.isEmpty)
                        StatusRow(title: "Latency", value: "\(String(format: "%.2f", result.publicIPCheck.latency))s", isGood: result.publicIPCheck.latency < 2.0)
                        
                        // Show IP comparison if both checks succeeded
                        if result.mullvadCheck.error == nil && result.publicIPCheck.error == nil {
                            let ipMatch = result.mullvadCheck.exitIP == result.publicIPCheck.ip
                            StatusRow(title: "IP Match", value: ipMatch ? "Yes" : "No", isGood: ipMatch)
                        }
                        
                        if let error = result.publicIPCheck.error {
                            Text("Error: \(error)")
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                    }
                } else {
                    EmptyView()
                }
            }
        }
    }
    
    private var deviceSection: some View {
        CollapsibleSection(
            title: "Device Metadata",
            isExpanded: expandedSections.contains(.device),
            onToggle: { toggleSection(.device) }
        ) {
            Group {
                if let result = opsecService.lastResult {
                    VStack(alignment: .leading, spacing: 8) {
                        StatusRow(title: "Device Name", value: result.deviceMetadata.deviceName, isGood: true)
                        StatusRow(title: "Model", value: result.deviceMetadata.modelIdentifier, isGood: true)
                        StatusRow(title: "OS Version", value: result.deviceMetadata.osVersion, isGood: true)
                        StatusRow(title: "Locale", value: result.deviceMetadata.locale, isGood: true)
                        StatusRow(title: "Region", value: result.deviceMetadata.region, isGood: true)
                        StatusRow(title: "Language", value: result.deviceMetadata.language, isGood: true)
                        StatusRow(title: "IDFV", value: String(result.deviceMetadata.identifierForVendor.prefix(8)) + "...", isGood: true)
                    }
                } else {
                    EmptyView()
                }
            }
        }
    }
    
    private var localNetworkSection: some View {
        CollapsibleSection(
            title: "Local Network",
            isExpanded: expandedSections.contains(.localNetwork),
            onToggle: { toggleSection(.localNetwork) }
        ) {
            Group {
                if let result = opsecService.lastResult {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(result.localNetwork, id: \.name) { interface in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(interface.name)
                                    .font(.headline)
                                    .foregroundColor(interface.isLoopback ? .secondary : .primary)
                                
                                if let ipv4 = interface.ipv4Address {
                                    StatusRow(title: "IPv4", value: ipv4, isGood: !interface.isLoopback)
                                }
                                if let ipv6 = interface.ipv6Address {
                                    StatusRow(title: "IPv6", value: ipv6, isGood: !interface.isLoopback)
                                }
                            }
                            .padding(.vertical, 4)
                        }
                    }
                } else {
                    EmptyView()
                }
            }
        }
    }
    
    private var dnsSection: some View {
        CollapsibleSection(
            title: "DNS Check",
            isExpanded: expandedSections.contains(.dns),
            onToggle: { toggleSection(.dns) }
        ) {
            Group {
                if let result = opsecService.lastResult {
                    VStack(alignment: .leading, spacing: 8) {
                        StatusRow(title: "Resolving", value: result.dnsCheck.isResolvingCorrectly ? "Yes" : "No", isGood: result.dnsCheck.isResolvingCorrectly)
                        StatusRow(title: "Latency", value: "\(String(format: "%.2f", result.dnsCheck.latency))s", isGood: result.dnsCheck.latency < 2.0)
                        
                        if let error = result.dnsCheck.error {
                            Text("Error: \(error)")
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                    }
                } else {
                    EmptyView()
                }
            }
        }
    }
    
    private var actionButtons: some View {
        HStack(spacing: 20) {
            Button("Re-run Checks") {
                Task {
                    await opsecService.runAllChecks()
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(opsecService.isRunning)
            .accessibilityLabel("Re-run OPSEC checks")
            .accessibilityHint("Performs all security checks again")
            
            if opsecService.lastResult != nil {
                Button("Export Report") {
                    exportText = opsecService.exportReport()
                    showingExportAlert = true
                }
                .buttonStyle(.bordered)
                .accessibilityLabel("Export OPSEC report")
                .accessibilityHint("Copies the security check report to clipboard")
            }
        }
    }
    
    private func toggleSection(_ section: SectionType) {
        if expandedSections.contains(section) {
            expandedSections.remove(section)
        } else {
            expandedSections.insert(section)
        }
    }
    
    private func statusColor(_ status: OPSECStatus) -> Color {
        switch status {
        case .pass: return .green
        case .warning: return .yellow
        case .fail: return .red
        }
    }
    
    private func formatTimestamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .medium
        return formatter.string(from: date)
    }
}

struct StatusRow: View {
    let title: String
    let value: String
    let isGood: Bool
    
    var body: some View {
        HStack {
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .font(.caption)
                .foregroundColor(isGood ? .primary : .red)
        }
    }
}

struct CollapsibleSection<Content: View>: View {
    let title: String
    let isExpanded: Bool
    let onToggle: () -> Void
    let content: () -> Content
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button(action: onToggle) {
                HStack {
                    Text(title)
                        .font(.headline)
                        .foregroundColor(.primary)
                    Spacer()
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .foregroundColor(.secondary)
                }
                .padding()
                .background(Color.gray.opacity(0.2))
            }
            .buttonStyle(PlainButtonStyle())
            .accessibilityLabel("\(title) section")
            .accessibilityHint(isExpanded ? "Tap to collapse" : "Tap to expand")
            .accessibilityAddTraits(.isButton)
            
            if isExpanded {
                content()
                    .padding()
                    .background(Color.black)
            }
        }
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.gray, lineWidth: 1)
        )
    }
}

#Preview {
    ContentView()
}
