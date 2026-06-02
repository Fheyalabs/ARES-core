// SPDX-License-Identifier: Apache-2.0

import Foundation

enum VotingFlow {
    static func run(serverURL: String, participants: Int, authSecret: String, sessionID: String) async throws -> Int {
        FileHandle.standardError.write(Data("voting: not yet implemented (L3-T7)\n".utf8))
        return 2
    }
}
