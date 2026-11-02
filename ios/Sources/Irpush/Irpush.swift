import CryptoKit
import Foundation
import IrpushC
import Network
import Security
import UserNotifications
#if canImport(UIKit)
import UIKit
#endif

/// irpush for iOS. Info.plist (app and extension): `IrpushGroup` = App Group (also the shared
/// Keychain access group); app only, optional: `IrpushRelays` = "https://push.you.example#hextoken".
/// iOS forbids sockets across apps, so apps of one team share the identity through the App Group
/// (one device id, one APNs route per app); each foreground app holds the socket while it runs.
public enum Irpush {
    public typealias Handler = (_ from: Data, _ app: Data, _ data: Data) -> Void
    nonisolated(unsafe) static var handler: Handler = { _, _, _ in }
    nonisolated(unsafe) static var monitor: NWPathMonitor?
    /// Relay changes: (url, onN0Fallback). Set before `start`; e.g. show "Using public relay" while true.
    nonisolated(unsafe) public static var relayChanged: (String?, Bool) -> Void = { _, _ in }

    static var group: String { Bundle.main.object(forInfoDictionaryKey: "IrpushGroup") as! String }
    static var path: String {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)!.appendingPathComponent("irpush.state").path
    }

    /// 32-byte state key in the Keychain; readable after first unlock so the extension works while locked.
    /// The app and the extension may race to create it: the loser re-reads the winner's key.
    static func kek() -> [UInt8]? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "irpush.kek", kSecAttrAccessGroup as String: group]
        func read() -> [UInt8]? {
            var r: CFTypeRef?
            guard SecItemCopyMatching(q.merging([kSecReturnData as String: true]) { $1 } as CFDictionary, &r) == errSecSuccess, let d = r as? Data, d.count == 32 else { return nil }
            return [UInt8](d)
        }
        if let k = read() { return k }
        var k = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &k) == errSecSuccess else { return nil }
        let add = q.merging([kSecValueData as String: Data(k), kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]) { $1 }
        switch SecItemAdd(add as CFDictionary, nil) {
        case errSecSuccess: return k
        case errSecDuplicateItem: return read()
        default: return nil
        }
    }

    private static let statusCb: irp_status_cb = { _, url, fallback in
        Irpush.relayChanged(url.map { String(cString: $0) }, fallback)
    }

    private static let cb: irp_cb = { _, from, app, data, len in
        Irpush.handler(Data(bytes: from!, count: 32), Data(bytes: app!, count: 16), Data(bytes: data!, count: len))
    }

    /// Call at launch. `ticket` only on first run (received in-band from a host, or scanned).
    /// Wires network changes and foreground/background automatically, and asks for push permission.
    @discardableResult
    public static func start(ticket: String? = nil, _ h: @escaping Handler) -> Bool {
        handler = h
        guard let k = kek() else { return false }
        _ = irp_status(statusCb, nil)
        let relays = Bundle.main.object(forInfoDictionaryKey: "IrpushRelays") as? String
        let ok = !FileManager.default.fileExists(atPath: path) && ticket != nil ? irp_join(path, k, ticket!, relays, cb, nil) == 0 : irp_open(path, k, relays, cb, nil) == 0
        guard ok else { return false }
        let m = NWPathMonitor()
        m.pathUpdateHandler = { p in // hashValue is reseeded per launch: the learned heartbeat must key on a stable id
            let d = SHA256.hash(data: Data((p.availableInterfaces.first?.name ?? "").utf8))
            irp_network(d.prefix(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) })
        }
        m.start(queue: .global(qos: .utility))
        monitor = m
        #if canImport(UIKit)
        let nc = NotificationCenter.default // backgrounded: close socket so hosts switch to APNs at once
        nc.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil) { _ in irp_pause(true) }
        nc.addObserver(forName: UIApplication.willEnterForegroundNotification, object: nil, queue: nil) { _ in irp_pause(false) }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
            if granted { DispatchQueue.main.async { UIApplication.shared.registerForRemoteNotifications() } }
        }
        #endif
        return true
    }

    /// From application(_:didRegisterForRemoteNotificationsWithDeviceToken:).
    public static func register(apnsToken t: Data) {
        #if DEBUG
        let sandbox = true
        #else
        let sandbox = false
        #endif
        t.withUnsafeBytes { _ = irp_route(sandbox, Bundle.main.bundleIdentifier!, $0.bindMemory(to: UInt8.self).baseAddress, t.count) }
    }

    /// This device's id; hosts push to it.
    public static var id: Data { var b = [UInt8](repeating: 0, count: 32); irp_id(&b); return Data(b) }

    /// 16-byte app address of a bundle id.
    public static func app(_ name: String) -> Data { var b = [UInt8](repeating: 0, count: 16); irp_app(name, &b); return Data(b) }

    /// Extension side: decrypt `userInfo["f"]`. nil: not ours or already delivered.
    public static func open(notification f: String) -> (from: Data, app: Data, data: Data)? {
        guard let k = kek() else { return nil }
        var from = [UInt8](repeating: 0, count: 32), app = [UInt8](repeating: 0, count: 16), out = [UInt8](repeating: 0, count: 1536)
        let n = irp_notification(path, k, f, &from, &app, &out, out.count)
        return n < 0 ? nil : (Data(from), Data(app), Data(out[..<n]))
    }
}

/// Subclass in your Notification Service Extension; override `render` to format your payload.
open class IrpushNotificationService: UNNotificationServiceExtension {
    open func render(app: Data, data: Data) -> (title: String, body: String) { ("", String(decoding: data, as: UTF8.self)) }

    override open func didReceive(_ request: UNNotificationRequest, withContentHandler done: @escaping (UNNotificationContent) -> Void) {
        guard let f = request.content.userInfo["f"] as? String, let m = Irpush.open(notification: f) else {
            return done(UNNotificationContent()) // duplicate: suppressed with the filtering entitlement, else placeholder
        }
        let c = request.content.mutableCopy() as! UNMutableNotificationContent
        (c.title, c.body) = render(app: m.app, data: m.data)
        c.userInfo = [:] // drop the sealed frame
        done(c)
    }
}
