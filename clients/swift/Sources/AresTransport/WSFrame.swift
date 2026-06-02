import Foundation
import AresClient   // DAGNode

public struct InboundFrame: Sendable {
    public let type: String
    public let sessionID: String
    public let seq: Int
    public let payload: Data?       // raw JSON bytes of the payload value, if present
    public let version: String
    public let raw: Data
}

public enum WSFrame {
    /// Encode an outbound frame. `payloadJSON` is the raw JSON bytes of the payload value,
    /// inlined verbatim (no re-encoding). A non-nil `lineage` sets version="2".
    public static func encodeOutbound(type: String, sessionID: String, seq: Int,
                                      payloadJSON: Data?, lineage: DAGNode?) throws -> Data {
        func esc(_ s: String) -> String {
            "\"" + s.replacingOccurrences(of: "\\", with: "\\\\")
                    .replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        var top: [String] = ["\"type\":\(esc(type))", "\"session_id\":\(esc(sessionID))", "\"seq\":\(seq)"]
        if let payloadJSON { top.append("\"payload\":\(String(decoding: payloadJSON, as: UTF8.self))") }
        if let lineage {
            top.append("\"version\":\"2\"")
            let lineageData = try JSONEncoder().encode(lineage)
            top.append("\"lineage\":\(String(decoding: lineageData, as: UTF8.self))")
        }
        return Data(("{" + top.joined(separator: ",") + "}").utf8)
    }

    public static func decodeInbound(_ raw: Data) throws -> InboundFrame {
        let obj = (try JSONSerialization.jsonObject(with: raw)) as? [String: Any] ?? [:]
        var payloadData: Data? = nil
        if let p = obj["payload"], !(p is NSNull) {
            payloadData = try JSONSerialization.data(withJSONObject: p, options: [])
        }
        let seq = (obj["seq"] as? NSNumber)?.intValue ?? (obj["seq"] as? Int) ?? 0
        return InboundFrame(
            type: obj["type"] as? String ?? "",
            sessionID: obj["session_id"] as? String ?? "",
            seq: seq, payload: payloadData,
            version: obj["version"] as? String ?? "", raw: raw)
    }
}
