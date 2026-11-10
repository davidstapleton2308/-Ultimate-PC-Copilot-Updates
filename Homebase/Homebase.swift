import SwiftUI
import Security
import CommonCrypto

enum HB {
    static let bg = Color(red: 0.025, green: 0.043, blue: 0.035)
    static let card = Color(red: 0.075, green: 0.102, blue: 0.086)
    static let edge = Color(red: 0.14, green: 0.21, blue: 0.17)
    static let green = Color(red: 0.46, green: 0.87, blue: 0.64)
    static let muted = Color(red: 0.58, green: 0.66, blue: 0.61)
}

final class HomeLock: ObservableObject {
    @Published var unlocked = false
    @Published var configured = false
    @Published var tries = 0
    @Published var lockedUntil: Date?
    private let service = "com.homebase.personal.pin"
    private let account = "pin.v1"
    init() { configured = read() != nil }
    private func read() -> Data? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                   kSecAttrService as String: service,
                                   kSecAttrAccount as String: account,
                                   kSecReturnData as String: true,
                                   kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }
    private func digest(_ pin: String, salt: Data) -> Data? {
        var bytes = [UInt8](repeating: 0, count: 32)
        let result: Int32 = salt.withUnsafeBytes { saltBytes in
            pin.withCString { password in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password,
                    pin.utf8.count,
                    saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 120000,
                    &bytes, bytes.count)
            }
        }
        return result == kCCSuccess ? Data(bytes) : nil
    }
    func create(_ pin: String) -> Bool {
        guard (6...12).contains(pin.count), pin.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return false }
        var salt = Data(count: 16)
        let code = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        guard code == errSecSuccess, let hash = digest(pin, salt: salt) else { return false }
        let query: [String:Any] = [kSecClass as String:kSecClassGenericPassword,
                                  kSecAttrService as String:service,
                                  kSecAttrAccount as String:account]
        SecItemDelete(query as CFDictionary)
        var attributes = query
        attributes[kSecValueData as String] = salt + hash
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else { return false }
        configured = true
        unlocked = true
        tries = 0
        return true
    }
    func verify(_ pin: String) -> Bool {
        if let until = lockedUntil, Date() < until { return false }
        guard let stored = read(), stored.count == 48,
              let result = digest(pin, salt: Data(stored.prefix(16))) else { return false }
        let expected = [UInt8](stored.suffix(32))
        let actual = [UInt8](result)
        var delta: UInt8 = 0
        for i in 0..<32 { delta |= expected[i] ^ actual[i] }
        if delta == 0 {
            tries = 0
            lockedUntil = nil
            unlocked = true
            return true
        }
        tries += 1
        if tries >= 5 {
            tries = 0
            lockedUntil = Date().addingTimeInterval(60)
        }
        return false
    }
    func lock() { unlocked = false }
}

@main
struct HomebaseApp: App {
    @StateObject private var lock = HomeLock()
    @Environment(\.scenePhase) private var phase
    var body: some Scene {
        WindowGroup {
            Group {
                if lock.unlocked {
                    HomeTabs().environmentObject(lock)
                } else {
                    PinEntry().environmentObject(lock)
                }
            }
            .preferredColorScheme(.dark)
            .onChange(of: phase) { newPhase in
                if newPhase != .active { lock.lock() }
            }
        }
    }
}

struct PinEntry: View {
    @EnvironmentObject private var lock: HomeLock
    @State private var pin = ""
    @State private var firstPin = ""
    @State private var message = ""
    var body: some View {
        ZStack {
            HB.bg.ignoresSafeArea()
            VStack(spacing: 22) {
                Spacer()
                Image(systemName: "house.lodge.fill")
                    .font(.system(size: 49))
                    .foregroundColor(HB.green)
                    .padding(22)
                    .background(HB.card, in: RoundedRectangle(cornerRadius: 28))
                Text("HOMEBASE")
                    .font(.system(size: 35, weight: .heavy, design: .rounded))
                    .tracking(3)
                Text(!lock.configured ? (firstPin.isEmpty ? "Create your private PIN" : "Confirm your PIN") : "Your private home, one place.")
                    .foregroundColor(HB.muted)
                SecureField("6–12 digit PIN", text: $pin)
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                    .padding(18)
                    .background(HB.card, in: RoundedRectangle(cornerRadius: 14))
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(HB.edge))
                    .frame(maxWidth: 330)
                if !message.isEmpty {
                    Text(message).font(.footnote).foregroundColor(.orange)
                }
                Button(action: submit) {
                    Text(lock.configured ? "Unlock Homebase" : (firstPin.isEmpty ? "Continue" : "Save PIN"))
                        .fontWeight(.bold)
                        .frame(maxWidth: 330)
                        .padding(18)
                        .background(HB.green, in: RoundedRectangle(cornerRadius: 14))
                        .foregroundColor(HB.bg)
                }
                Spacer()
                Text("Local PIN lock • iPhone & iPad")
                    .font(.caption).foregroundColor(HB.muted)
            }
            .padding(24)
        }
    }
    private func submit() {
        if !lock.configured {
            guard (6...12).contains(pin.count), pin.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
                message = "Enter 6–12 digits."
                return
            }
            if firstPin.isEmpty {
                firstPin = pin
                pin = ""
                message = ""
            } else if pin == firstPin {
                if !lock.create(pin) { message = "Could not save PIN to Keychain." }
            } else {
                message = "PINs do not match. Start over."
                pin = ""
                firstPin = ""
            }
        } else {
            let okay = lock.verify(pin)
            pin = ""
            message = okay ? "" : "Incorrect PIN, or temporarily locked after multiple attempts."
        }
    }
}

struct HomeTile: Identifiable {
    let id: String
    let title: String
    let description: String
    let symbol: String
}
let tiles: [HomeTile] = [
    .init(id:"laptop", title:"Gaming Laptop", description:"Windows bridge planned", symbol:"laptopcomputer"),
    .init(id:"games", title:"Game Launcher", description:"Game integrations planned", symbol:"gamecontroller.fill"),
    .init(id:"lights", title:"Smart Lighting", description:"Provider not connected", symbol:"lightbulb.fill"),
    .init(id:"tv", title:"Fire TV", description:"Remote control planned", symbol:"tv.fill"),
    .init(id:"camera", title:"Cameras", description:"No camera connected", symbol:"video.fill"),
    .init(id:"mop", title:"Robot Mop", description:"Cleaning control planned", symbol:"circle.hexagongrid.fill")
]

struct HomeTabs: View {
    var body: some View {
        TabView {
            Overview().tabItem { Label("Home", systemImage: "house.fill") }
            LaptopDashboard().tabItem { Label("Laptop", systemImage: "laptopcomputer") }
            Devices().tabItem { Label("Devices", systemImage: "square.grid.2x2.fill") }
            Scenes().tabItem { Label("Scenes", systemImage: "sparkles") }
            HomeSettings().tabItem { Label("Settings", systemImage: "gearshape.fill") }
        }
        .accentColor(HB.green)
    }
}

struct HBPage<Content: View>: View {
    let content: Content
    init(@ViewBuilder content: () -> Content) { self.content = content() }
    var body: some View {
        ZStack {
            HB.bg.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 22) { content }
                    .frame(maxWidth: 800, alignment: .leading)
                    .padding(.horizontal, 20).padding(.top, 28).padding(.bottom, 35)
                    .frame(maxWidth: .infinity)
            }
        }
    }
}
struct Panel<Content: View>: View {
    let content: Content
    init(@ViewBuilder content: () -> Content) { self.content = content() }
    var body: some View {
        VStack(alignment:.leading, spacing:12) { content }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(19)
            .background(HB.card, in: RoundedRectangle(cornerRadius: 19))
            .overlay(RoundedRectangle(cornerRadius: 19).stroke(HB.edge))
    }
}
struct Overview: View {
    @AppStorage("homebase.name") var homeName = "My Home"
    private let columns = [GridItem(.adaptive(minimum: 155), spacing: 12)]
    var body: some View {
        HBPage {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("HOMEBASE").font(.caption.bold()).tracking(3).foregroundColor(HB.green)
                    Text(homeName).font(.system(size: 34, weight: .bold, design: .rounded))
                }
                Spacer()
                Image(systemName: "house.fill").font(.title2)
                    .frame(width: 48, height: 48)
                    .background(HB.card, in: RoundedRectangle(cornerRadius: 16))
                    .foregroundColor(HB.green)
            }
            Panel {
                Text("YOUR COMMAND CENTER").font(.caption.bold()).tracking(1.2).foregroundColor(HB.green)
                Text("One home. Every device.")
                    .font(.system(size: 27, weight: .bold, design: .rounded))
                Text("Your personal dashboard starts here. Connect devices in upcoming updates.")
                    .font(.subheadline).foregroundColor(HB.muted)
                Label("PIN-protected dashboard", systemImage: "lock.shield")
                    .font(.caption).foregroundColor(HB.green)
            }
            Text("Your spaces").font(.title2.bold())
            HStack(spacing: 12) {
                Panel {
                    Image(systemName: "sofa.fill").foregroundColor(HB.green)
                    Text("Living Room").font(.headline)
                    Text("Not configured").font(.caption).foregroundColor(HB.muted)
                }
                Panel {
                    Image(systemName: "bed.double.fill").foregroundColor(HB.green)
                    Text("Bedroom").font(.headline)
                    Text("Not configured").font(.caption).foregroundColor(HB.muted)
                }
            }
            Text("Quick access").font(.title2.bold())
            LazyVGrid(columns: columns, spacing: 12) {
                ForEach(tiles.prefix(4)) { t in
                    Panel {
                        Image(systemName: t.symbol).font(.title).foregroundColor(HB.green)
                        Text(t.title).font(.headline)
                        Text("Not connected").font(.caption).foregroundColor(HB.muted)
                    }
                }
            }
            Text("Devices are previews, not active controls.")
                .font(.footnote).foregroundColor(HB.muted)
        }
    }
}
struct Devices: View {
    var body: some View {
        HBPage {
            Text("Devices").font(.largeTitle.bold())
            Text("Connect and manage devices here as support is added.")
                .foregroundColor(HB.muted)
            ForEach(tiles) { t in
                Panel {
                    Label(t.title, systemImage: t.symbol).font(.headline).foregroundColor(HB.green)
                    Text(t.description).font(.subheadline).foregroundColor(HB.muted)
                    Text("Not connected").font(.caption.bold())
                }
            }
        }
    }
}
struct Scenes: View {
    var body: some View {
        HBPage {
            Text("Scenes").font(.largeTitle.bold())
            Text("One touch, multiple devices—when integrations are added.")
                .foregroundColor(HB.muted)
            ForEach(["Good Morning", "Movie Night", "Gaming Mode", "Good Night"], id: \.self) { name in
                Panel {
                    Label(name, systemImage:"sparkles").font(.headline).foregroundColor(HB.green)
                    Text("Coming soon").font(.caption).foregroundColor(HB.muted)
                }
            }
        }
    }
}
struct HomeSettings: View {
    @EnvironmentObject private var lock: HomeLock
    @AppStorage("homebase.name") private var homeName = "My Home"
    var body: some View {
        HBPage {
            Text("Settings").font(.largeTitle.bold())
            Panel {
                Label("Home name", systemImage: "house").foregroundColor(HB.green)
                TextField("Home name", text: $homeName)
                    .textFieldStyle(.roundedBorder)
            }
            Panel {
                Label("Security", systemImage: "lock.shield").foregroundColor(HB.green)
                Text("PIN stored securely in the iOS Keychain.")
                    .font(.subheadline).foregroundColor(HB.muted)
                Button("Lock Homebase") { lock.lock() }
                    .font(.headline).foregroundColor(HB.green)
            }
            Panel {
                Text("Homebase 1.0").font(.headline)
                Text("Local dashboard only. Devices have not been paired.")
                    .font(.subheadline).foregroundColor(HB.muted)
            }
        }
    }
}
