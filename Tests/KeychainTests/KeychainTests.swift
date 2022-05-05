import XCTest
@testable import Keychain

final class KeychainTests: XCTestCase {
    static let exampleCreator : UInt32 = 0x75547374; /* corresponds to 'uTst' */

    func testAddAndRetrieve() {
        let password = UUID().uuidString
        let keychain = Keychain.default
        
        do {
            try keychain.delete(passwordFor: "user", on: "server")
            try keychain.add(password: password, for: "user", on: "server")
            let retrieved = try keychain.password(for: "user", on: "server")
            XCTAssertEqual(password, retrieved)
        } catch {
            XCTFail("error: \(error)")
        }
    }

    func testAddAndRetrieveWithCreator() {
        let password = UUID().uuidString
        let keychain = Keychain.default
        
        do {
            try keychain.delete(passwordFor: "user", on: "server")
            try keychain.add(password: password, for: "user", on: "server", creator: Self.exampleCreator)
            let retrieved = try keychain.password(for: "user", on: "server")
            XCTAssertEqual(password, retrieved)
        } catch {
            XCTFail("error: \(error)")
        }
    }

    func testUpdate() {
        let password = UUID().uuidString
        let keychain = Keychain.default
        
        do {
            
            try keychain.delete(passwordFor: "user", on: "server")
            try keychain.add(password: password, for: "user", on: "server")
            try keychain.update(password: "new password", for: "user", on: "server")
            let retrieved = try keychain.password(for: "user", on: "server")
            XCTAssertEqual(retrieved, "new password")
        } catch {
            XCTFail("error: \(error)")
        }
    }

    func testDelete() {
        let server = UUID().uuidString
        let password = UUID().uuidString
        let keychain = Keychain.default
        
        do {
            try keychain.add(password: password, for: "user", on: server)
            let retrieved = try keychain.password(for: "user", on: server)
            XCTAssertEqual(password, retrieved)
            try keychain.delete(passwordFor: "user", on: server)
            let missing = try? keychain.password(for: "user", on: server)
            XCTAssertNil(missing)
        } catch {
            XCTFail("error: \(error)")
        }
    }

    func testDeleteByCreator() {
        let server = UUID().uuidString
        let password = UUID().uuidString
        let keychain = Keychain.default
        
        do {
            try keychain.add(password: password, for: "user", on: server, creator: Self.exampleCreator)
            let retrieved = try keychain.password(for: "user", on: server)
            XCTAssertEqual(password, retrieved)
            try keychain.delete(allPasswordsCreatedBy: Self.exampleCreator)
            let missing = try? keychain.password(for: "user", on: server)
            XCTAssertNil(missing)
        } catch {
            XCTFail("error: \(error)")
        }
    }
}
