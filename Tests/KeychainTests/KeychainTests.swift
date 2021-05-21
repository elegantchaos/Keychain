import XCTest
@testable import Keychain

final class KeychainTests: XCTestCase {
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
}
