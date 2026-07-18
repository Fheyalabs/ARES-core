// SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import AresClientFHE

final class EncryptedDistanceTests: FHETestCase {
    func testBFVEncryptedSquaredDistanceIsRepeatedAcrossSlots() throws {
        let ctx = try BFVCryptoContext(
            ringDim: 1024,
            multiplicativeDepth: 4,
            plaintextModulus: 65_537,
            batchSize: 8
        )
        let share = try ctx.singleKeyGen()
        let originFirst = try ctx.encryptRepeatedScalarBFV(10, publicKey: share.publicKey)
        let originSecond = try ctx.encryptRepeatedScalarBFV(20, publicKey: share.publicKey)

        let distance = try ctx.encryptedSquaredDistanceBFV(
            originFirst: originFirst,
            originSecond: originSecond,
            localFirst: 7,
            localSecond: 24
        )
        let ciphertext = try ctx.deserializeCiphertext(distance)
        let partial = try ctx.partialDecrypt(ciphertext, with: share.secretKey)
        XCTAssertEqual(try ctx.fuseInt([partial], slotCapacity: 8), Array(repeating: 25, count: 8))
    }

    func testBFVEncryptedSquaredDistanceRejectsMalformedOriginCiphertext() throws {
        let ctx = try BFVCryptoContext(
            ringDim: 1024,
            multiplicativeDepth: 4,
            plaintextModulus: 65_537,
            batchSize: 8
        )
        _ = try ctx.singleKeyGen()
        XCTAssertThrowsError(try ctx.encryptedSquaredDistanceBFV(
            originFirst: Data([0x01]),
            originSecond: Data([0x02]),
            localFirst: 0,
            localSecond: 0
        ))
    }

    func testEncryptedSquaredDistanceIsRepeatedAcrossSlots() throws {
        let ctx = try CryptoContext(
            ringDim: 1024,
            scalingFactor: Double(UInt64(1) << 50),
            depth: 4,
            batchSize: 128
        )
        let share = try ctx.singleKeyGen()
        let originFirst = try ctx.encryptRepeatedScalar(10, publicKey: share.publicKey)
        let originSecond = try ctx.encryptRepeatedScalar(20, publicKey: share.publicKey)

        let distance = try ctx.encryptedSquaredDistance(
            originFirst: originFirst,
            originSecond: originSecond,
            localFirst: 7,
            localSecond: 24
        )
        let ciphertext = try ctx.deserializeCiphertext(distance)
        let partial = try ctx.partialDecrypt(ciphertext, with: share.secretKey)
        let slots = try ctx.fuse([partial], slotCapacity: 128)

        XCTAssertEqual(slots.count, 128)
        for (index, slot) in slots.enumerated() {
            XCTAssertEqual(slot, 25, accuracy: 0.1, "slot \(index)")
        }
    }

    func testEncryptedSquaredDistanceRejectsMalformedOriginCiphertext() throws {
        let ctx = try CryptoContext(
            ringDim: 1024,
            scalingFactor: Double(UInt64(1) << 50),
            depth: 4,
            batchSize: 128
        )
        XCTAssertThrowsError(try ctx.encryptedSquaredDistance(
            originFirst: Data([0x01]),
            originSecond: Data([0x02]),
            localFirst: 0,
            localSecond: 0
        ))
    }
}
