// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//  Created by Sam Deane on 06/04/2020.
//  All code (c) 2020 - present day, Elegant Chaos Limited.
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

import Foundation
import Security

public struct Keychain {
    
    public static let `default` = Keychain()
    
    public enum KeychainError: Error {
        case unhandledError(status: OSStatus)
        case unexpectedPasswordData
    }
    
    /// The kind of items this object works with.
    public let kind: CFString

    /// Creates an object for interacting with a certain type of keychain object.
    public init(kind: CFString = kSecClassInternetPassword) {
        self.kind = kind
    }
    
    /// Returns a dictionary describing a keychain item.
    internal func itemSpec(for user: String, on server: String, creator: UInt32? = nil) -> NSMutableDictionary {
        let spec: NSMutableDictionary = [
            kSecClass: kind,
            kSecAttrAccount: user,
            kSecAttrServer: server
        ]
        
        if let creator = creator {
            spec[kSecAttrCreator] = creator as CFNumber
        }
        
        return spec
    }
    
    /// Returns the password entry for a given user/server pair.
    /// If no password entry exists, we don't throw an error, but return nil.
    /// Other keychain errors are wrapped and thrown.
    public func password(for user: String, on server: String) throws -> String? {
        let query = itemSpec(for: user, on: server)
        query[kSecMatchLimit] = kSecMatchLimitOne
        query[kSecReturnAttributes] = true
        query[kSecReturnData] = true
        
        var item: CFTypeRef? = nil
        let status = SecItemCopyMatching(query, &item)
        guard status != errSecItemNotFound else { return nil }
        guard status == errSecSuccess else { throw KeychainError.unhandledError(status: status) }
        
        guard let existingItem = item as? [CFString: Any],
              let passwordData = existingItem[kSecValueData] as? Data,
              let password = String(data: passwordData, encoding: String.Encoding.utf8)
        else {
            throw KeychainError.unexpectedPasswordData
        }
        
        return password
    }
    
    /// Add a new password entry for a user/server pair.
    /// We optionally take a creator code which can be used later to delete any matching passwords.
    public func add(password: String, for user: String, on server: String, creator: UInt32? = nil) throws {
        let tokenData = password.data(using: .utf8)!
        let attributes = itemSpec(for: user, on: server, creator: creator)
        attributes[kSecValueData] = tokenData
        
        let status = SecItemAdd(attributes, nil)
        guard status == errSecSuccess else { throw KeychainError.unhandledError(status: status) }
    }
    
    /// Update an existing password entry if it exists.
    /// If no entry existed, we create one.
    public func update(password: String, for user: String, on server: String, creator: UInt32? = nil) throws {
        let tokenData = password.data(using: .utf8)!
        let query = itemSpec(for: user, on: server, creator: creator)
        let update: NSDictionary = [
            kSecValueData: tokenData
        ]
        
        let status = SecItemUpdate(query, update)
        switch status {
            case errSecItemNotFound:
                try add(password: password, for: user, on: server, creator: creator)
                
            case errSecSuccess:
                break
                
            default:
                throw KeychainError.unhandledError(status: status)
        }
    }
    
    /// Remove the first keychain entry for a given user/server (and optionally, creator).
    /// If the entry didn't exist, we don't throw any errors.
    public func delete(passwordFor user: String, on server: String, creator: UInt32? = nil) throws {
        let query = itemSpec(for: user, on: server, creator: creator)
        let status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unhandledError(status: status)
        }
    }

    /// Delete all password entries with a given creator tag.
    /// The creator code is a 32 bit number, generally interpreted as an
    /// old-school 4-char OSType. If you tag any entries that you create
    /// with a creator, you can later use this call to remove them all.
    /// Entries created by the user in some other way are unlikely to have
    /// the same creator, so should be left untouched.
    public func delete(allPasswordsCreatedBy appID: UInt32) throws {
        let query: NSMutableDictionary = [
            kSecClass: kind,
            kSecAttrCreator: appID as CFNumber
        ]

        #if os(macOS)
            //
            query[kSecMatchLimit] = kSecMatchLimitAll
        #endif

        var item: CFTypeRef? = nil
        repeat  {
            var status = SecItemCopyMatching(query, &item)
            if status == errSecItemNotFound {
                return
            }
            
            status = SecItemDelete(query)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeychainError.unhandledError(status: status)
            }
        } while(true)
    }
}
