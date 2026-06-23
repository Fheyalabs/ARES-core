// SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import AresClientFHE

final class BFVRoundTripTests: FHETestCase {
    func testBFVPackedIntRoundTrip() throws {
        let ctx = try BFVCryptoContext(
            ringDim: 8192,
            multiplicativeDepth: 4,
            plaintextModulus: 65537,
            batchSize: 8
        )
        let first = try ctx.keyGenFirst()
        let second = try ctx.keyGenNext(prev: first.publicKey)
        let ct = try ctx.encrypt(intValues: [-3, 0, 42, -1], under: second.publicKey)
        let p0 = try ctx.partialDecrypt(ct, with: first.secretKey)
        let p1 = try ctx.partialDecrypt(ct, with: second.secretKey)
        let out = try ctx.fuseInt([p0, p1], slotCapacity: 4)
        XCTAssertEqual(out, [-3, 0, 42, -1])
    }
}
