// CoreBluetooth peripheral I/O only. Keys, Noise and Shum packets stay in Rust.
import Foundation
import CoreBluetooth

let serviceID = CBUUID(string: "F85FC602-7866-4F4C-90AB-4F14E107792B")
let characteristicID = CBUUID(string: "8F85918D-468D-4FBE-825A-CBD890B74D10")
func emit(_ value: [String: Any]) {
    guard let bytes = try? JSONSerialization.data(withJSONObject: value) else { return }
    FileHandle.standardOutput.write(bytes + Data([10]))
}
final class PeripheralRadio: NSObject, CBPeripheralManagerDelegate {
    var manager: CBPeripheralManager!
    var characteristic: CBMutableCharacteristic?
    var subscribers: [String: CBCentral] = [:]
    var pending: [(String, Data)] = []
    var timer: Timer?
    override init() {
        super.init()
        manager = CBPeripheralManager(delegate: self, queue: .main,
            options: [CBPeripheralManagerOptionShowPowerAlertKey: true])
        timer = Timer.scheduledTimer(withTimeInterval: 0.025, repeats: true) { [weak self] _ in self?.drain() }
    }
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        let state: String
        switch peripheral.state {
        case .poweredOn: state = "poweredOn"
        case .poweredOff: state = "poweredOff"
        case .unauthorized: state = "unauthorized"
        case .unsupported: state = "unsupported"
        case .resetting: state = "resetting"
        default: state = "unknown"
        }
        emit(["kind": "state", "state": state])
        if peripheral.state == .poweredOn {
            let value = CBMutableCharacteristic(type: characteristicID,
                properties: [.notify, .write, .writeWithoutResponse, .read], value: nil,
                permissions: [.readable, .writeable])
            let service = CBMutableService(type: serviceID, primary: true)
            service.characteristics = [value]; characteristic = value
            manager.removeAllServices(); manager.add(service)
        } else {
            for id in subscribers.keys { emit(["kind": "disconnected", "id": id]) }
            subscribers.removeAll(); pending.removeAll(); characteristic = nil
            emit(["kind": "writable"])
        }
    }
    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        if let error { emit(["kind": "error", "error": error.localizedDescription]); return }
        peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [serviceID]])
    }
    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error { emit(["kind": "error", "error": error.localizedDescription]) }
        else { emit(["kind": "advertising"]) }
    }
    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        guard characteristic.uuid == characteristicID else { return }
        let id = "p:" + central.identifier.uuidString
        guard subscribers[id] != nil || subscribers.count < 12 else { return }
        subscribers[id] = central
        emit(["kind": "connected", "id": id, "budget": min(512, central.maximumUpdateValueLength)])
    }
    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        let id = "p:" + central.identifier.uuidString
        subscribers.removeValue(forKey: id); pending.removeAll { $0.0 == id }
        if pending.isEmpty { emit(["kind": "writable"]) }
        emit(["kind": "disconnected", "id": id])
    }
    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        guard request.characteristic.uuid == characteristicID, request.offset == 0 else {
            peripheral.respond(to: request, withResult: .invalidOffset); return
        }
        request.value = Data(); peripheral.respond(to: request, withResult: .success)
    }
    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        // CoreBluetooth delivers a long-write batch atomically. Do not forward partial ATT values.
        var assembled: [String: Data] = [:]
        var complete: [(String, Data)] = []
        for request in requests {
            guard request.characteristic.uuid == characteristicID, let value = request.value else {
                if let first = requests.first { peripheral.respond(to: first, withResult: .requestNotSupported) }; return
            }
            let id = "p:" + request.central.identifier.uuidString
            if request.offset == 0, let prior = assembled.removeValue(forKey: id) { complete.append((id, prior)) }
            var data = assembled[id] ?? Data()
            guard request.offset == data.count, data.count + value.count <= 1_000_000 else {
                if let first = requests.first { peripheral.respond(to: first, withResult: .invalidOffset) }; return
            }
            data.append(value); assembled[id] = data
        }
        if let first = requests.first { peripheral.respond(to: first, withResult: .success) }
        complete.append(contentsOf: assembled.map { ($0.key, $0.value) })
        for (id, bytes) in complete { emit(["kind": "data", "id": id, "data": bytes.base64EncodedString()]) }
    }
    func command(_ value: [String: Any]) {
        guard let id = value["to"] as? String, let values = value["frames"] as? [String],
              let central = subscribers[id], pending.count + values.count <= 2048 else {
            emit(["kind": "error", "error": "BLE subscriber unavailable"]); emit(["kind": "writable"]); return
        }
        var batch: [(String, Data)] = []
        for value in values {
            guard let data = Data(base64Encoded: value), data.count <= central.maximumUpdateValueLength else {
                emit(["kind": "error", "error": "BLE notification exceeds negotiated budget"]); emit(["kind": "writable"]); return
            }
            batch.append((id, data))
        }
        pending.append(contentsOf: batch)
    }
    func drain() {
        guard let characteristic, let (id, data) = pending.first else { return }
        guard let central = subscribers[id] else { pending.removeFirst(); return }
        if manager.updateValue(data, for: characteristic, onSubscribedCentrals: [central]) {
            pending.removeFirst()
            if pending.isEmpty { emit(["kind": "writable"]) }
        }
        // false means backpressure: retain the exact head frame until the next ready callback/tick.
    }
    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) { drain() }
}
let radio = PeripheralRadio()
DispatchQueue.global(qos: .utility).async {
    while let line = readLine(strippingNewline: true) {
        guard line.utf8.count <= 2_000_000, let bytes = line.data(using: .utf8),
              let command = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any] else { continue }
        DispatchQueue.main.async { radio.command(command) }
    }
    DispatchQueue.main.async { radio.manager.stopAdvertising(); radio.manager.removeAllServices(); exit(0) }
}
RunLoop.main.run()
