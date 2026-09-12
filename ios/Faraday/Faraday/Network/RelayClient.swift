import Foundation

struct TransparencyView: Decodable {
    var mailboxes: Int
    var pendingEnvelopes: Int
    var plaintextBodies: Int
    var decryptionKeys: Int
}

struct InboxEnvelope: Decodable {
    var id: String
    var blob: String
    var bytes: Int
    var at: Int64
}

actor RelayClient {
    var baseURL: URL
    private var socket: URLSessionWebSocketTask?
    private var session = URLSession(configuration: .ephemeral)

    init(baseURL: URL) {
        self.baseURL = baseURL
    }

    func setBase(_ url: URL) {
        baseURL = url
    }

    func register(mailbox: String, token: String) async throws {
        var req = URLRequest(url: baseURL.appending(path: "/v1/mailbox"))
        req.httpMethod = "PUT"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: ["mailbox": mailbox, "token": token])
        let (_, res) = try await session.data(for: req)
        try expectOK(res)
    }

    func drop(to: String, blob: Data) async throws {
        var req = URLRequest(url: baseURL.appending(path: "/v1/drop"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: [
            "to": to,
            "blob": blob.base64EncodedString()
        ])
        let (_, res) = try await session.data(for: req)
        try expectOK(res)
    }

    func inbox(mailbox: String, token: String) async throws -> [InboxEnvelope] {
        var req = URLRequest(url: baseURL.appending(path: "/v1/inbox"))
        req.setValue(mailbox, forHTTPHeaderField: "X-Faraday-Mailbox")
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, res) = try await session.data(for: req)
        try expectOK(res)
        return try JSONDecoder().decode(InboxDTO.self, from: data).envelopes
    }

    func ack(mailbox: String, token: String, ids: [String]) async throws {
        var req = URLRequest(url: baseURL.appending(path: "/v1/ack"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(mailbox, forHTTPHeaderField: "X-Faraday-Mailbox")
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.httpBody = try JSONSerialization.data(withJSONObject: ["ids": ids])
        let (_, res) = try await session.data(for: req)
        try expectOK(res)
    }

    func transparency() async throws -> TransparencyView {
        let (data, res) = try await session.data(from: baseURL.appending(path: "/v1/transparency"))
        try expectOK(res)
        return try JSONDecoder().decode(TransparencyView.self, from: data)
    }

    func connect(mailbox: String, token: String, onDeliver: @escaping @Sendable (InboxEnvelope) -> Void) async {
        disconnect()
        var components = URLComponents(url: baseURL.appending(path: "/v1/ws"), resolvingAgainstBaseURL: false)
        if components?.scheme == "http" { components?.scheme = "ws" }
        if components?.scheme == "https" { components?.scheme = "wss" }
        guard let url = components?.url else { return }
        let task = session.webSocketTask(with: url)
        socket = task
        task.resume()
        let hello: [String: Any] = ["v": 1, "op": "auth", "mailbox": mailbox, "token": token]
        guard let data = try? JSONSerialization.data(withJSONObject: hello),
              let text = String(data: data, encoding: .utf8) else { return }
        try? await task.send(.string(text))
        receiveLoop(task: task, onDeliver: onDeliver)
    }

    func disconnect() {
        socket?.cancel(with: .goingAway, reason: nil)
        socket = nil
    }

    nonisolated private func receiveLoop(task: URLSessionWebSocketTask, onDeliver: @escaping @Sendable (InboxEnvelope) -> Void) {
        task.receive { result in
            switch result {
            case .success(.string(let text)):
                if let data = text.data(using: .utf8),
                   let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   obj["op"] as? String == "deliver",
                   let id = obj["id"] as? String,
                   let blob = obj["blob"] as? String {
                    let env = InboxEnvelope(id: id, blob: blob, bytes: obj["bytes"] as? Int ?? 0, at: obj["at"] as? Int64 ?? 0)
                    onDeliver(env)
                }
                self.receiveLoop(task: task, onDeliver: onDeliver)
            case .success:
                self.receiveLoop(task: task, onDeliver: onDeliver)
            case .failure:
                break
            }
        }
    }

    private func expectOK(_ res: URLResponse) throws {
        guard let http = res as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw FaradayNetworkError.badStatus
        }
    }
}

private struct InboxDTO: Decodable { var envelopes: [InboxEnvelope] }

enum FaradayNetworkError: Error, LocalizedError {
    case badStatus, badURL
    var errorDescription: String? {
        switch self {
        case .badStatus: return "中繼站拒絕了請求。請檢查網址，並確認伺服器正在執行。"
        case .badURL: return "中繼站網址無效。"
        }
    }
}
