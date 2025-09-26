//
//  SettingsView.swift
//  fadsf
//
//  Created by Johan Sandgren on 2025-09-26.
//

import SwiftUI

struct SettingsView: View {
    @ObservedObject var opsecService: OPSECCheckService
    @Environment(\.dismiss) private var dismiss
    @State private var mullvadEndpoint: String
    @State private var ipifyEndpoint: String
    @State private var showingExportAlert = false
    @State private var exportText = ""
    
    init(opsecService: OPSECCheckService) {
        self.opsecService = opsecService
        self._mullvadEndpoint = State(initialValue: opsecService.mullvadEndpoint)
        self._ipifyEndpoint = State(initialValue: opsecService.ipifyEndpoint)
    }
    
    var body: some View {
        NavigationView {
            Form {
                Section("Network Endpoints") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Mullvad Check Endpoint")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        TextField("Mullvad endpoint", text: $mullvadEndpoint)
                    }
                    
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Public IP Check Endpoint")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        TextField("IPify endpoint", text: $ipifyEndpoint)
                    }
                }
                
                Section("Export") {
                    Button("Export Last Report") {
                        exportText = opsecService.exportReport()
                        showingExportAlert = true
                    }
                    .disabled(opsecService.lastResult == nil)
                }
                
                Section("About") {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("OPSEC Check for tvOS")
                            .font(.headline)
                        Text("Version 1.0.0")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("Privacy-first OPSEC verification tool")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Save") {
                        saveSettings()
                        dismiss()
                    }
                }
            }
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
    
    private func saveSettings() {
        opsecService.mullvadEndpoint = mullvadEndpoint
        opsecService.ipifyEndpoint = ipifyEndpoint
    }
}

#Preview {
    SettingsView(opsecService: OPSECCheckService())
}
