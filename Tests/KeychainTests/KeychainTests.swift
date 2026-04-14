import Security
import XCTest
@testable import Keychain

final class KeychainTests: XCTestCase {
    static let exampleCreator : UInt32 = 0x75547374; /* corresponds to 'uTst' */

    private func makeExecutableTestKeychain() -> Keychain {
        #if os(macOS)
            // `swift test` runs without the entitlement required by the
            // data protection backend, so integration-style tests use the
            // file-based backend while separate assertions cover the default.
            Keychain(storage: .fileBased)
        #else
            .default
        #endif
    }

    #if os(macOS)
    func testDefaultStorageUsesDataProtection() throws {
        guard #available(macOS 10.15, *) else { return }
        let keychain = Keychain()

        let spec = keychain.itemSpec(for: "unittest", on: "server")

        XCTAssertEqual(spec[kSecUseDataProtectionKeychain] as? Bool, true)
    }

    func testDataProtectionStorageAddsBackendFlag() throws {
        guard #available(macOS 10.15, *) else { return }
        let keychain = Keychain(storage: .dataProtection)

        let spec = keychain.itemSpec(for: "unittest", on: "server")

        XCTAssertEqual(spec[kSecUseDataProtectionKeychain] as? Bool, true)
    }

    func testFileBasedStorageOmitsBackendFlag() throws {
        guard #available(macOS 10.15, *) else { return }
        let keychain = Keychain(storage: .fileBased)

        let spec = keychain.itemSpec(for: "unittest", on: "server")

        XCTAssertNil(spec[kSecUseDataProtectionKeychain])
    }
    #endif

    func testAddAndRetrieve() throws {
        let password = UUID().uuidString
        let keychain = makeExecutableTestKeychain()
        
        try keychain.delete(passwordFor: "unittest", on: "server")
        try keychain.add(password: password, for: "unittest", on: "server")
        let retrieved = try keychain.password(for: "unittest", on: "server")
        XCTAssertEqual(password, retrieved)
    }

    func testAddUsingUpdate() throws {
        let password = UUID().uuidString
        let keychain = makeExecutableTestKeychain()

        try keychain.delete(passwordFor: "unittest", on: "server")
        try keychain.update(password: password, for: "unittest", on: "server")
        let retrieved = try keychain.password(for: "unittest", on: "server")
        XCTAssertEqual(password, retrieved)
    }

    func testAddAndRetrieveWithCreator() throws {
        let password = UUID().uuidString
        let keychain = makeExecutableTestKeychain()
        
        try keychain.delete(passwordFor: "unittest", on: "server")
        try keychain.add(password: password, for: "unittest", on: "server", creator: Self.exampleCreator)
        let retrieved = try keychain.password(for: "unittest", on: "server")
        XCTAssertEqual(password, retrieved)
    }

    func testAddUsingUpdateWithCreator() throws {
        let password = UUID().uuidString
        let keychain = makeExecutableTestKeychain()
        
        try keychain.delete(passwordFor: "unittest", on: "server")
        try keychain.update(password: password, for: "unittest", on: "server", creator: Self.exampleCreator)
        let retrieved = try keychain.password(for: "unittest", on: "server")
        XCTAssertEqual(password, retrieved)
    }

    func testUpdate() throws {
        let password = UUID().uuidString
        let keychain = makeExecutableTestKeychain()
        
        try keychain.delete(passwordFor: "unittest", on: "server")
        try keychain.add(password: password, for: "unittest", on: "server")
        try keychain.update(password: "new password", for: "unittest", on: "server")
        let retrieved = try keychain.password(for: "unittest", on: "server")
        XCTAssertEqual(retrieved, "new password")
    }


    func testUpdateWithCreator() throws {
        let password = UUID().uuidString
        let keychain = makeExecutableTestKeychain()
        
        try keychain.delete(passwordFor: "unittest", on: "server")
        try keychain.add(password: password, for: "unittest", on: "server", creator: Self.exampleCreator)
        try keychain.update(password: "new password", for: "unittest", on: "server", creator: Self.exampleCreator)
        let retrieved = try keychain.password(for: "unittest", on: "server")
        XCTAssertEqual(retrieved, "new password")
    }

    func testDelete() throws {
        let server = UUID().uuidString
        let password = UUID().uuidString
        let keychain = makeExecutableTestKeychain()
        
        try keychain.add(password: password, for: "unittest", on: server)
        let retrieved = try keychain.password(for: "unittest", on: server)
        XCTAssertEqual(password, retrieved)
        try keychain.delete(passwordFor: "unittest", on: server)
        let missing = try? keychain.password(for: "unittest", on: server)
        XCTAssertNil(missing)
    }

    func testDeleteByCreator() throws {
        let server = UUID().uuidString
        let password = UUID().uuidString
        let keychain = makeExecutableTestKeychain()
        
        try keychain.add(password: password, for: "unittest1", on: server, creator: Self.exampleCreator)
        try keychain.add(password: password, for: "unittest2", on: server, creator: Self.exampleCreator)
        XCTAssertEqual(password, try keychain.password(for: "unittest1", on: server))
        XCTAssertEqual(password, try keychain.password(for: "unittest2", on: server))

        try keychain.delete(allPasswordsCreatedBy: Self.exampleCreator)
        XCTAssertNil(try? keychain.password(for: "unittest1", on: server))
        XCTAssertNil(try? keychain.password(for: "unittest2", on: server))
    }
}
