import XCTest
import Crypto
@testable import AresClient

final class LineageVectorsTests: XCTestCase {
    func testGoldenVectorsConformance() throws {
        let vectors = try GoldenVectorLoader.loadNodeVectors()
        XCTAssertEqual(vectors.count, 2, "expected 2 golden vectors")
        for v in vectors {
            let seed = ByteUtil.fromHex(v.input.ed25519_seed_hex)!
            let payload = ByteUtil.fromHex(v.input.payload_hex)!
            let r = try Lineage.buildSlotNode(
                sessionID: v.input.session_id, payloadBytes: payload, ed25519Seed: seed,
                parentsHex: v.input.parents_hex, phaseID: v.input.phase_id, role: v.input.role)

            // 1) Deterministic fields: byte-for-byte vs Go/Python.
            XCTAssertEqual(r.node.producer, v.expected.producer_hex, "\(v.name): producer")
            XCTAssertEqual(r.node.payloadHash, v.expected.payload_hash_hex, "\(v.name): payload_hash")
            XCTAssertEqual(r.node.hash, v.expected.node_hash_hex, "\(v.name): node_hash")
            XCTAssertEqual(r.node.algorithm, v.expected.algorithm, "\(v.name): algorithm")

            // 2) The EXACT signed bytes match the golden signing_msg (proves the signing
            //    input is byte-identical to Go). Reconstruct: node_hash ‖ lp(sid)‖lp(phase)‖lp(role).
            var signingMsg = ByteUtil.fromHex(r.node.hash)!
            signingMsg.append(ByteUtil.lp(Data(v.input.session_id.utf8)))
            signingMsg.append(ByteUtil.lp(Data(v.input.phase_id.utf8)))
            signingMsg.append(ByteUtil.lp(Data(v.input.role.utf8)))
            XCTAssertEqual(ByteUtil.hex(signingMsg), v.expected.signing_msg_hex, "\(v.name): signing_msg")

            // 3) Signature VERIFIES under producer over signing_msg (swift-crypto Ed25519 is
            //    randomized, so it is valid-but-not-byte-equal to the golden signature).
            let pub = try Curve25519.Signing.PublicKey(rawRepresentation: ByteUtil.fromHex(r.node.producer)!)
            let sig = ByteUtil.fromHex(r.node.signature)!
            XCTAssertTrue(pub.isValidSignature(sig, for: signingMsg), "\(v.name): signature must verify")
            XCTAssertEqual(sig.count, 64, "\(v.name): Ed25519 signature is 64 bytes")
        }
    }
}
