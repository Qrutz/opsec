//
//  OPSEChistoryManager.swift
//  fadsf
//
//  Created by Johan Sandgren on 2025-09-26.
//

import Foundation
import Security

class OPSEChistoryManager: ObservableObject {
    @Published var history: [OPSEChResult] = []
    private let maxHistoryCount = 10
    private let keychainService = "com.opsec.check.history"
    private let keychainAccount = "encryption_key"
    
    init() {
        loadHistory()
    }
    
    func addResult(_ result: OPSEChResult) {
        history.insert(result, at: 0)
        
        // Keep only the last N results
        if history.count > maxHistoryCount {
            history = Array(history.prefix(maxHistoryCount))
        }
        
        saveHistory()
    }
    
    func clearHistory() {
        history.removeAll()
        saveHistory()
    }
    
    private func loadHistory() {
        guard let data = loadEncryptedData() else { return }
        
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            history = try decoder.decode([OPSEChResult].self, from: data)
        } catch {
            history = []
        }
    }
    
    private func saveHistory() {
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(history)
            saveEncryptedData(data)
        } catch {
            // Silent fail for production
        }
    }
    
    private func getOrCreateEncryptionKey() -> Data? {
        // Try to retrieve existing key
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess, let keyData = result as? Data {
            return keyData
        }
        
        // Create new key if none exists
        var keyData = Data(count: 32)
        let result2 = keyData.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, 32, bytes.bindMemory(to: UInt8.self).baseAddress!)
        }
        
        guard result2 == errSecSuccess else { return nil }
        
        // Store the new key
        let storeQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: keyData
        ]
        
        let storeStatus = SecItemAdd(storeQuery as CFDictionary, nil)
        guard storeStatus == errSecSuccess else { return nil }
        
        return keyData
    }
    
    private func saveEncryptedData(_ data: Data) {
        guard let key = getOrCreateEncryptionKey() else { return }
        
        let encryptedData = encryptData(data, withKey: key)
        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let fileURL = documentsPath.appendingPathComponent("opsec_history.encrypted")
        
        do {
            try encryptedData.write(to: fileURL)
        } catch {
            // Silent fail for production
        }
    }
    
    private func loadEncryptedData() -> Data? {
        guard let key = getOrCreateEncryptionKey() else { return nil }
        
        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let fileURL = documentsPath.appendingPathComponent("opsec_history.encrypted")
        
        guard let encryptedData = try? Data(contentsOf: fileURL) else { return nil }
        
        return decryptData(encryptedData, withKey: key)
    }
    
    private func encryptData(_ data: Data, withKey key: Data) -> Data {
        // Simple XOR encryption for demonstration
        // In production, use proper encryption like AES
        var encrypted = Data()
        let keyBytes = key.withUnsafeBytes { $0.bindMemory(to: UInt8.self) }
        let dataBytes = data.withUnsafeBytes { $0.bindMemory(to: UInt8.self) }
        
        for (index, byte) in dataBytes.enumerated() {
            let keyByte = keyBytes[index % keyBytes.count]
            encrypted.append(byte ^ keyByte)
        }
        
        return encrypted
    }
    
    private func decryptData(_ encryptedData: Data, withKey key: Data) -> Data {
        // XOR decryption (same as encryption for XOR)
        return encryptData(encryptedData, withKey: key)
    }
}

// MARK: - OPSEChResult Codable Extension

extension OPSEChResult: Codable {
    enum CodingKeys: String, CodingKey {
        case timestamp
        case overallStatus
        case mullvadCheck
        case publicIPCheck
        case deviceMetadata
        case localNetwork
        case dnsCheck
        case latency
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        overallStatus = try container.decode(OPSECStatus.self, forKey: .overallStatus)
        mullvadCheck = try container.decode(MullvadCheckResult.self, forKey: .mullvadCheck)
        publicIPCheck = try container.decode(PublicIPCheckResult.self, forKey: .publicIPCheck)
        deviceMetadata = try container.decode(DeviceMetadata.self, forKey: .deviceMetadata)
        localNetwork = try container.decode([NetworkInterface].self, forKey: .localNetwork)
        dnsCheck = try container.decode(DNSCheckResult.self, forKey: .dnsCheck)
        latency = try container.decode(TimeInterval.self, forKey: .latency)
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(timestamp, forKey: .timestamp)
        try container.encode(overallStatus, forKey: .overallStatus)
        try container.encode(mullvadCheck, forKey: .mullvadCheck)
        try container.encode(publicIPCheck, forKey: .publicIPCheck)
        try container.encode(deviceMetadata, forKey: .deviceMetadata)
        try container.encode(localNetwork, forKey: .localNetwork)
        try container.encode(dnsCheck, forKey: .dnsCheck)
        try container.encode(latency, forKey: .latency)
    }
}

