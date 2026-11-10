import SwiftUI
import Security
import CryptoKit
import AVFoundation

private let tokenService = "com.homebase.personal.laptop"

private enum LaptopSecrets {
    static func read() -> String {
        let query: [String: Any] = [
            kSecClass as String:kSecClassGenericPassword,
            kSecAttrService as String:tokenService,
            kSecAttrAccount as String:"windows.token",
            kSecMatchLimit as String:kSecMatchLimitOne,
            kSecReturnData as String:true
        ]
        var value: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &value) == errSecSuccess,
              let data = value as? Data else { return "" }
        return String(data: data, encoding: .utf8) ?? ""
    }
    static func write(_ token: String) -> Bool {
        clear()
        let attributes: [String:Any] = [
            kSecClass as String:kSecClassGenericPassword,
            kSecAttrService as String:tokenService,
            kSecAttrAccount as String:"windows.token",
            kSecAttrAccessible as String:kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String:Data(token.utf8)
        ]
        return SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess
    }
    static func clear() {
        let query: [String:Any] = [
            kSecClass as String:kSecClassGenericPassword,
            kSecAttrService as String:tokenService,
            kSecAttrAccount as String:"windows.token"
        ]
        SecItemDelete(query as CFDictionary)
    }
}

private final class PinnedTrust: NSObject, URLSessionDelegate {
    let fingerprint: String
    init(_ fingerprint: String) { self.fingerprint = fingerprint.lowercased() }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let certificate = SecTrustGetCertificateAtIndex(trust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let data = SecCertificateCopyData(certificate) as Data
        let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        if actual == fingerprint {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

final class LaptopLink: ObservableObject {
    @Published var paired = false
    @Published var online = false
    @Published var hostname = "Windows laptop"
    @Published var message = "Pair Homebase with the companion running on your laptop."
    @Published var cpu = 0
    @Published var memory = 0
    @Published var battery: Int?
    @Published var charging: Bool?
    @Published var playnite = false
    @Published var steam = false
    @Published var busy = false

    private var ip = UserDefaults.standard.string(forKey:"homebase.laptop.ip") ?? ""
    private var fp = UserDefaults.standard.string(forKey:"homebase.laptop.fp") ?? ""
    private var token = LaptopSecrets.read()
    init() {
        paired = !ip.isEmpty && fp.count == 64 && !token.isEmpty
    }

    private static func validLocalIPv4(_ value: String) -> Bool {
        let octets = value.split(separator: ".").compactMap { Int($0) }
        guard octets.count == 4 && value.split(separator: ".").count == 4,
              octets.allSatisfy({ (0...255).contains($0) }) else { return false }
        return octets[0] == 10 ||
            (octets[0] == 172 && (16...31).contains(octets[1])) ||
            (octets[0] == 192 && octets[1] == 168)
    }

    private static func send(ip: String, fp: String, token: String?,
                             path: String, body: [String:String]?,
                             completion: @escaping ([String:Any]?, String?) -> Void) {
        guard let url = URL(string:"https://" + ip + ":47655" + path) else {
            completion(nil, "Invalid connection address")
            return
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 8
        configuration.timeoutIntervalForResource = 10
        let delegate = PinnedTrust(fp)
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        var request = URLRequest(url: url)
        request.timeoutInterval = 8
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("application/json", forHTTPHeaderField:"Accept")
        if let token = token {
            request.setValue(token, forHTTPHeaderField:"X-Homebase-Token")
        }
        if let body = body {
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField:"Content-Type")
            request.httpBody = try? JSONSerialization.data(withJSONObject:body)
        }
        let task = session.dataTask(with: request) { data, response, error in
            var json: [String:Any]?
            if let data = data {
                json = (try? JSONSerialization.jsonObject(with:data)) as? [String:Any]
            }
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            let text: String?
            if code == 200 {
                text = nil
            } else if let detail = json?["error"] as? String {
                text = detail
            } else {
                text = error?.localizedDescription ?? "Could not reach the laptop. Check Wi-Fi and Windows Firewall."
            }
            DispatchQueue.main.async { completion(json, text) }
            session.finishTasksAndInvalidate()
        }
        task.resume()
    }

    func pair(qrText: String) {
        guard let bytes = qrText.data(using: .utf8),
              let json = (try? JSONSerialization.jsonObject(with: bytes)) as? [String:Any],
              let host = json["ip"] as? String,
              let code = json["code"] as? String,
              let fingerprint = json["fp"] as? String,
              let port = json["port"] as? Int, port == 47655,
              json["v"] as? Int == 1,
              Self.validLocalIPv4(host),
              fingerprint.count == 64,
              fingerprint.unicodeScalars.allSatisfy({ ("0"..."9").contains(String($0)) || ("a"..."f").contains(String($0).lowercased()) }),
              code.count == 6,
              code.allSatisfy({ $0.isNumber }) else {
            message = "Invalid pairing QR. Scan the code shown by Homebase Companion."
            return
        }
        busy = true
        message = "Pairing securely..."
        Self.send(ip:host, fp:fingerprint, token:nil, path:"/pair", body:["code":code]) { [weak self] response, error in
            guard let self = self else { return }
            self.busy = false
            guard let newToken = response?["token"] as? String, error == nil,
                  LaptopSecrets.write(newToken) else {
                self.message = error ?? "Unable to store pairing credentials"
                return
            }
            self.ip = host
            self.fp = fingerprint.lowercased()
            self.token = newToken
            UserDefaults.standard.set(host, forKey:"homebase.laptop.ip")
            UserDefaults.standard.set(self.fp, forKey:"homebase.laptop.fp")
            self.paired = true
            self.message = "Paired successfully."
            self.refresh()
        }
    }
    func refresh() {
        guard paired else { return }
        busy = true
        Self.send(ip:ip, fp:fp, token:token, path:"/status", body:nil) { [weak self] response, error in
            guard let self = self else { return }
            self.busy = false
            if let data = response, error == nil {
                self.online = true
                self.hostname = data["name"] as? String ?? "Windows laptop"
                self.cpu = data["cpu"] as? Int ?? 0
                self.memory = data["memory"] as? Int ?? 0
                self.battery = data["battery"] as? Int
                self.charging = data["charging"] as? Bool
                self.playnite = data["playnite"] as? Bool ?? false
                self.steam = data["steam"] as? Bool ?? false
                self.message = "Connected over encrypted local Wi-Fi."
            } else {
                self.online = false
                self.message = error ?? "Laptop unavailable"
            }
        }
    }
    func command(_ action: String) {
        guard paired && online else { return }
        message = "Sending command..."
        Self.send(ip:ip, fp:fp, token:token, path:"/command", body:["action":action]) { [weak self] response, error in
            guard let self = self else { return }
            self.message = error ?? "Command sent: " + action.replacingOccurrences(of:"_", with:" ")
            if action == "sleep" || action == "lock" {
                self.online = false
            }
        }
    }
    func forget() {
        LaptopSecrets.clear()
        token = ""
        ip = ""
        fp = ""
        UserDefaults.standard.removeObject(forKey:"homebase.laptop.ip")
        UserDefaults.standard.removeObject(forKey:"homebase.laptop.fp")
        paired = false
        online = false
        message = "Laptop disconnected. Pair it again using a new QR code."
    }
}

struct LaptopDashboard: View {
    @StateObject private var link = LaptopLink()
    @State private var showScanner = false
    @State private var showManual = false
    @State private var manualData = ""
    @State private var confirmSleep = false
    private let grid = [GridItem(.flexible(),spacing:12),GridItem(.flexible(),spacing:12)]
    var body: some View {
        HBPage {
            HStack {
                VStack(alignment:.leading, spacing: 6) {
                    Text("LAPTOP CONTROL")
                        .font(.caption.bold()).tracking(2).foregroundColor(HB.green)
                    Text("Your Windows PC")
                        .font(.largeTitle.bold())
                }
                Spacer()
                Image(systemName:"laptopcomputer")
                    .foregroundColor(HB.green).font(.largeTitle)
            }
            Panel {
                HStack {
                    Circle().fill(link.online ? HB.green : Color.gray)
                        .frame(width: 11, height: 11)
                    Text(link.online ? "Connected" : (link.paired ? "Offline" : "Not paired"))
                        .font(.headline)
                    Spacer()
                    if link.paired {
                        Button(action: { link.refresh() }) {
                            Image(systemName:"arrow.clockwise")
                                .foregroundColor(HB.green)
                        }
                        .disabled(link.busy)
                    }
                }
                Text(link.hostname).font(.title3.bold())
                Text(link.message).font(.subheadline).foregroundColor(HB.muted)
            }
            if !link.paired {
                Panel {
                    Label("Connect your laptop", systemImage:"qrcode.viewfinder")
                        .font(.title3.bold()).foregroundColor(HB.green)
                    Text("Open Homebase Companion on Windows. With both devices on the same Wi-Fi, scan the pairing QR shown on your laptop.")
                        .font(.subheadline).foregroundColor(HB.muted)
                    Button(action:{ showScanner = true }) {
                        Label("Scan laptop QR code", systemImage:"camera.viewfinder")
                            .frame(maxWidth:.infinity).padding(14)
                            .background(HB.green, in:RoundedRectangle(cornerRadius:13))
                            .foregroundColor(HB.bg).font(.headline)
                    }
                    Button("Paste pairing data instead") { showManual = true }
                        .foregroundColor(HB.green).font(.subheadline)
                }
            } else {
                if link.online {
                    Text("System").font(.title2.bold())
                    LazyVGrid(columns:grid,spacing:12) {
                        Panel {
                            Label("CPU", systemImage:"cpu").foregroundColor(HB.green)
                            Text("\(link.cpu)%").font(.title2.bold())
                        }
                        Panel {
                            Label("Memory", systemImage:"memorychip").foregroundColor(HB.green)
                            Text("\(link.memory)%").font(.title2.bold())
                        }
                        if let charge = link.battery {
                            Panel {
                                Label("Battery", systemImage:"battery.100").foregroundColor(HB.green)
                                Text("\(charge)%").font(.title2.bold())
                            }
                        }
                    }
                    Text("Controls").font(.title2.bold())
                    Panel {
                        Label("Volume", systemImage:"speaker.wave.2.fill").font(.headline).foregroundColor(HB.green)
                        HStack(spacing:12) {
                            controlButton("–", symbol:"speaker.minus.fill", action:"volume_down")
                            controlButton("Mute", symbol:"speaker.slash.fill", action:"mute")
                            controlButton("+", symbol:"speaker.plus.fill", action:"volume_up")
                        }
                    }
                    Text("Launch apps").font(.title2.bold())
                    HStack(spacing:12) {
                        appButton("Playnite", symbol:"gamecontroller.fill", installed:link.playnite, action:"playnite")
                        appButton("Steam", symbol:"gamecontroller", installed:link.steam, action:"steam")
                    }
                    Text("Security & power").font(.title2.bold())
                    HStack(spacing:12) {
                        appButton("Lock laptop", symbol:"lock.fill", installed:true, action:"lock")
                        Panel {
                            Button(action:{ confirmSleep = true }) {
                                Label("Sleep", systemImage:"moon.zzz.fill")
                                    .font(.subheadline.bold()).foregroundColor(HB.green)
                                    .frame(maxWidth:.infinity)
                            }
                        }
                    }
                }
                Button("Forget this laptop") { link.forget() }
                    .font(.footnote).foregroundColor(HB.muted)
            }
            Text("Local Wi-Fi only. Homebase will not control the laptop when the companion is closed or the PC is asleep.")
                .font(.footnote).foregroundColor(HB.muted)
        }
        .onAppear { link.refresh() }
        .alert("Put laptop to sleep?",isPresented:$confirmSleep) {
            Button("Cancel",role:.cancel) { }
            Button("Sleep",role:.destructive) { link.command("sleep") }
        } message: {
            Text("The laptop may not wake remotely; use its keyboard or power button.")
        }
        .sheet(isPresented:$showScanner) {
            NavigationView {
                ZStack {
                    Color.black.ignoresSafeArea()
                    PairingScanner { value in
                        showScanner = false
                        link.pair(qrText:value)
                    }
                    VStack {
                        Spacer()
                        Text("Point your camera at the QR code displayed on Windows")
                            .font(.footnote.bold())
                            .multilineTextAlignment(.center)
                            .padding()
                            .background(Color.black.opacity(0.7),in:RoundedRectangle(cornerRadius:12))
                            .padding(.bottom,36)
                    }
                }
                .navigationTitle("Pair Windows laptop")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement:.navigationBarLeading) {
                    Button("Cancel") { showScanner = false }
                }}
            }
        }
        .sheet(isPresented:$showManual) {
            NavigationView {
                Form {
                    Section(header:Text("Pairing data")) {
                        Text("Use the Copy Pairing Data button in the Windows companion, then paste the text here.")
                        TextEditor(text:$manualData).frame(height:140)
                    }
                    Button("Pair laptop") {
                        showManual = false
                        link.pair(qrText:manualData.trimmingCharacters(in:.whitespacesAndNewlines))
                    }
                }
                .navigationTitle("Manual pairing")
                .toolbar { ToolbarItem(placement:.navigationBarLeading) {
                    Button("Cancel") { showManual = false }
                }}
            }
        }
    }
    private func controlButton(_ label: String, symbol: String, action: String) -> some View {
        Button(action:{ link.command(action) }) {
            VStack(spacing:5) {
                Image(systemName:symbol).font(.title3)
                Text(label).font(.caption.bold())
            }
            .frame(maxWidth:.infinity).padding(12)
            .background(HB.bg,in:RoundedRectangle(cornerRadius:12))
        }
        .foregroundColor(HB.green)
    }
    private func appButton(_ label:String, symbol:String,installed:Bool,action:String) -> some View {
        Panel {
            Button(action:{ link.command(action) }) {
                VStack(alignment:.leading,spacing:7) {
                    Image(systemName:symbol).font(.title2).foregroundColor(HB.green)
                    Text(label).font(.subheadline.bold()).foregroundColor(.white)
                    Text(installed ? "Ready" : "Not detected")
                        .font(.caption).foregroundColor(HB.muted)
                }
                .frame(maxWidth:.infinity,alignment:.leading)
            }
            .disabled(!installed)
        }
    }
}

struct PairingScanner: UIViewControllerRepresentable {
    var onScan: (String) -> Void
    func makeUIViewController(context:Context) -> CameraController {
        let vc = CameraController()
        vc.onScan = onScan
        return vc
    }
    func updateUIViewController(_ uiViewController:CameraController,context:Context) {}
}

final class CameraController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    private let capture = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?
    private var handled = false
    var onScan: ((String) -> Void)?
    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        guard let camera = AVCaptureDevice.default(for:.video),
              let input = try? AVCaptureDeviceInput(device: camera),
              capture.canAddInput(input) else { return }
        capture.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard capture.canAddOutput(output) else { return }
        capture.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue:.main)
        output.metadataObjectTypes = [.qr]
        let layer = AVCaptureVideoPreviewLayer(session:capture)
        layer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(layer)
        preview = layer
    }
    override func viewWillAppear(_ animated:Bool) {
        super.viewWillAppear(animated)
        DispatchQueue.global(qos:.userInitiated).async { [weak self] in
            self?.capture.startRunning()
        }
    }
    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
    }
    override func viewWillDisappear(_ animated:Bool) {
        super.viewWillDisappear(animated)
        DispatchQueue.global(qos:.userInitiated).async { [weak self] in
            self?.capture.stopRunning()
        }
    }
    func metadataOutput(_ output:AVCaptureMetadataOutput, didOutput metadataObjects:[AVMetadataObject],
                        from connection:AVCaptureConnection) {
        guard !handled, let qr = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let text = qr.stringValue else { return }
        handled = true
        onScan?(text)
    }
}
