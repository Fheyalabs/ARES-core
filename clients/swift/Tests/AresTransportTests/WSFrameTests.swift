import XCTest
import Crypto
@testable import AresTransport

final class WSFrameTests: XCTestCase {
    func testAuthTokenMatchesHMACSHA256Hex() {
        let token = Session.deriveAuthToken(secret: "s3cret", pseudonym: "bidder-00")
        let expected = HMAC<SHA256>.authenticationCode(
            for: Data("bidder-00".utf8), using: SymmetricKey(data: Data("s3cret".utf8)))
        XCTAssertEqual(token, expected.map { String(format: "%02x", $0) }.joined())
        XCTAssertEqual(token.count, 64)
    }
    func testOutboundFrameV1OmitsLineageAndVersion() throws {
        let data = try WSFrame.encodeOutbound(type: "auction.bid",
            sessionID: "s1", seq: 0, payloadJSON: Data(#"{"bid_ct":"aa"}"#.utf8), lineage: nil)
        let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(obj["type"] as? String, "auction.bid")
        XCTAssertEqual(obj["session_id"] as? String, "s1")
        XCTAssertNil(obj["lineage"]); XCTAssertNil(obj["version"])
        XCTAssertNotNil(obj["payload"])
    }
    func testInboundFrameDecodes() throws {
        let raw = Data(#"{"type":"auction.invitation","session_id":"s1","seq":3}"#.utf8)
        let f = try WSFrame.decodeInbound(raw)
        XCTAssertEqual(f.type, "auction.invitation"); XCTAssertEqual(f.sessionID, "s1"); XCTAssertEqual(f.seq, 3)
    }
}
