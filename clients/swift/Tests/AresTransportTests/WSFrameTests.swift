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

    func testReconnectRequestIncludesExactResumeCursor() throws {
        let request = try Session.webSocketRequest(
            serverURL: "https://api.example.test/base",
            pseudonym: "bidder-00",
            authToken: "token",
            headers: ["X-Client-Version": "22"],
            resumeAfter: 42
        )

        let components = try XCTUnwrap(URLComponents(url: try XCTUnwrap(request.url), resolvingAgainstBaseURL: false))
        XCTAssertEqual(components.scheme, "wss")
        XCTAssertEqual(components.path, "/v2/ws")
        XCTAssertEqual(components.queryItems?.first(where: { $0.name == "pseudonym" })?.value, "bidder-00")
        XCTAssertEqual(components.queryItems?.first(where: { $0.name == "auth" })?.value, "token")
        XCTAssertEqual(components.queryItems?.first(where: { $0.name == "resume_after" })?.value, "42")
        XCTAssertEqual(request.value(forHTTPHeaderField: "X-Client-Version"), "22")
    }

    func testInitialRequestOmitsResumeCursor() throws {
        let request = try Session.webSocketRequest(
            serverURL: "https://api.example.test",
            pseudonym: "bidder-00"
        )

        let components = try XCTUnwrap(URLComponents(url: try XCTUnwrap(request.url), resolvingAgainstBaseURL: false))
        XCTAssertNil(components.queryItems?.first(where: { $0.name == "resume_after" }))
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

    func testInboundFramePreservesRawPayloadBytesWithStandardBase64Slashes() throws {
        let payload = Data(#"{"frame":"////"}"#.utf8)
        let raw = try WSFrame.encodeOutbound(
            type: "phased.message",
            sessionID: "s1",
            seq: 1,
            payloadJSON: payload,
            lineage: nil
        )

        let frame = try WSFrame.decodeInbound(raw)
        XCTAssertEqual(frame.payload, payload)
    }

    func testInboundFramePreservesNestedPayloadWhitespaceAndStrings() throws {
        let payload = Data(#"{ "nested" : [ { "frame" : "////" } ], "note" : "a } , [ string" }"#.utf8)
        let raw = try WSFrame.encodeOutbound(
            type: "phased.message",
            sessionID: "s1",
            seq: 1,
            payloadJSON: payload,
            lineage: nil
        )

        let frame = try WSFrame.decodeInbound(raw)
        XCTAssertEqual(frame.payload, payload)
    }
}
