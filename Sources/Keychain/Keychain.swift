// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//  Created by Sam Deane on 06/04/2020.
//  All code (c) 2020 - present day, Elegant Chaos Limited.
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

import Foundation
import Security

public struct Keychain {

    public static let `default` = Keychain()
    
    public enum KeychainError: Error {
        case noPassword
        case unhandledError(status: OSStatus)
        case unexpectedPasswordData
    }
    
    public init() {
    }
    
    internal func query(for user: String, on server: String) -> NSDictionary {
        let query: NSDictionary = [
            kSecClass: kSecClassInternetPassword,
            kSecAttrAccount: user,
            kSecAttrServer: server,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnAttributes: true,
            kSecReturnData: true
        ]

        return query
    }
    
    public func password(for user: String, on server: String) throws -> String {
        let query = query(for: user, on: server)
        
        var item: CFTypeRef? = nil
        let status = SecItemCopyMatching(query, &item)
        guard status != errSecItemNotFound else { throw KeychainError.noPassword }
        guard status == errSecSuccess else { throw KeychainError.unhandledError(status: status) }
        
        guard let existingItem = item as? [CFString : Any],
            let passwordData = existingItem[kSecValueData] as? Data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8)
            else {
                throw KeychainError.unexpectedPasswordData
        }
        
        return password
    }

    public func add(password: String, for user: String, on server: String) throws {
        let tokenData = password.data(using: .utf8)!
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrAccount as String: user,
                                    kSecAttrServer as String: server,
                                    kSecValueData as String: tokenData]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.unhandledError(status: status) }
    }
    
    public func update(password: String, for user: String, on server: String) throws {
        let tokenData = password.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrAccount as String: user,
            kSecAttrServer as String: server,
        ]

        let update: [String: Any] = [
            kSecValueData as String: tokenData
        ]
        
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        switch status {
            case errSecItemNotFound:
                try add(password: password, for: user, on: server)
                
            case errSecSuccess:
                break
                
            default:
                throw KeychainError.unhandledError(status: status)
        }
    }
    
    public func delete(passwordFor user: String, on server: String) throws {
        let query = query(for: user, on: server)
        let status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.unhandledError(status: status) }
    }
}

/// Deprecated API

extension Keychain {
    @available(*, deprecated, message: "use add(password:for:on:) instead") public func addToken(_ token: String, user: String, server: String) throws {
        try add(password: token, for: user, on: server)
    }

    @available(*, deprecated, message: "use password(for:on:) instead") public func getToken(user: String, server: String) throws -> String {
        return try password(for: user, on: server)
    }
}
