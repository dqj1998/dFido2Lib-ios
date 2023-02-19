//
//  Utils.swift
//  dFido2LibCore
//
//  Created by Du Qingjie on 2022/08/14.
//

import Foundation

extension DataProtocol {
    var data: Data { .init(self) }
    var hexa: String { map { .init(format: "%02x", $0) }.joined() }
    
}

extension Data {
    public var encodedHexadecimals: [UInt8] {
        return self.withUnsafeBytes { pointer -> [UInt8] in
            guard let address = pointer
                    .bindMemory(to: UInt8.self)
                    .baseAddress else { return [] }
            return [UInt8](UnsafeBufferPointer(start: address, count: self.count))
        }
    }
}

public enum ErrorType : String, Error {
    case badData = "fido2.badData"
    case badOperation = "fido2.badOperation"
    case invalidState = "fido2.invalidState"
    case constraint = "fido2.constraint"
    case cancelled = "fido2.cancelled"
    case timeout = "fido2.timeout"
    case notAllowed = "fido2.notAllowed"
    case notSupported = "fido2.notSupported"
    case typeError = "fido2.typeError"
    case unknown = "fido2.unknown"
}
public class Fido2Error :Error{
    public var error: ErrorType
    public var details: NSError?
    
    init(
        error:      ErrorType   = .unknown,
        details:    NSError?    = nil
      ) {
          self.error   = error
          self.details = details
      }
    
    public static func new (
        error:      ErrorType   = .unknown,
        message:    String?     = nil
    ) -> Fido2Error{
        let err = Fido2Error(error: error)
        if (message != nil) {
            err.details = NSError(domain: "fido2lib", code: 1, userInfo: [NSLocalizedDescriptionKey:message ?? ""])
        }
        
        return err
    }
    
    public static func new (
        error:      ErrorType   = .unknown,
        details:    Error
    ) -> Fido2Error{
        return Fido2Error(error: error, details: details as NSError)
    }
    
    
}

public class Fido2Logger {
    enum level:String{
        case err    = "err"
        case info   = "info"
        case debug  = "debug"
    }

    public static var enable_debug: Bool = false

    public static func debug(_ msg: String) {
        if enable_debug {
            log(level: .debug, msg: msg)
        }
    }
    
    public static func info(_ msg: String) {
        log(level: .info, msg: msg)
    }
    
    public static func err(_ msg: String) {
        log(level: .err, msg: msg)
    }
    
    private static func log(level: level, msg: String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMddHHmmss"
        let dateString = formatter.string(from: Date())
        print("\(dateString) [Fido2Logger-" + level.rawValue + "]" + msg)
    }
}

public class KeyTools {
    
    public static func saveKey(keyChainId: String, handle: String, key: Data) throws {
        
        let keychain = Keychain(service: keyChainId)
        
        try keychain.set(key, key: handle)
    }
    
    public static func retrieveKey(keyChainId: String, handle: String) throws -> Data? {
        
        let keychain = Keychain(service: keyChainId)
        
        if let rtn = try keychain.getData(handle) {
            return rtn
        }
        return nil
    }
    
    public static func deleteKey(keyChainId: String, handle: String) throws {
        
        let keychain = Keychain(service: keyChainId)
        
        do {
            try keychain.remove(handle)
        } catch let error {
            Fido2Logger.debug("deleteKey fail: \(error)")
            throw Fido2Error.new(error: .unknown, message: "deleteKey fail: \(error)")
        }
        
    }
    
    public static func clearKey(keyChainIdPrefix: String, handle: String?=nil) throws {
        if nil == handle || handle!.isEmpty{
            try Keychain.removeAll(ServicePrefix: keyChainIdPrefix)
        }else{
            try deleteKey(keyChainId: keyChainIdPrefix, handle: handle!)
        }
        
    }
}

public func checkDevice()throws{
    if(!LibConfig.enableJailBroken && isJailBroken()){
        Fido2Logger.err("A JailBroken device or Simulator!")
        throw Fido2Error.new(error: .unknown, message: "LibErr101: A JailBroken device or Simulator!")
    }
}

func isJailBroken() -> Bool{
    if JailBrokenHelper.isSimulator() { return true }
    if JailBrokenHelper.isContainsSuspiciousApps() { return true }
    if JailBrokenHelper.isSuspiciousSystemPathsExists() { return true }
    return JailBrokenHelper.canEditSystemFiles()
}

private struct JailBrokenHelper {
    static func isSimulator() -> Bool {
        return TARGET_OS_SIMULATOR != 0
    }
    
    //Check if suspicious apps (Cydia, FakeCarrier, Icy etc.) is installed
    static func isContainsSuspiciousApps() -> Bool {
        for path in suspiciousAppsPathToCheck {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
    
    //Check if system contains suspicious files
    static func isSuspiciousSystemPathsExists() -> Bool {
        for path in suspiciousSystemPathsToCheck {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
    
    //Check if app can edit system files
    static func canEditSystemFiles() -> Bool {
        let jailBreakText = "Developer Insider"
        do {
            try jailBreakText.write(toFile: jailBreakText, atomically: true, encoding: .utf8)
            return true
        } catch {
            return false
        }
    }
    
    //suspicious apps path to check
    static var suspiciousAppsPathToCheck: [String] {
        return ["/Applications/Cydia.app",
                "/Applications/blackra1n.app",
                "/Applications/FakeCarrier.app",
                "/Applications/Icy.app",
                "/Applications/IntelliScreen.app",
                "/Applications/MxTube.app",
                "/Applications/RockApp.app",
                "/Applications/SBSettings.app",
                "/Applications/WinterBoard.app"
        ]
    }
    
    //suspicious system paths to check
    static var suspiciousSystemPathsToCheck: [String] {
        return ["/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
                "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
                "/private/var/lib/apt",
                "/private/var/lib/apt/",
                "/private/var/lib/cydia",
                "/private/var/mobile/Library/SBSettings/Themes",
                "/private/var/stash",
                "/private/var/tmp/cydia.log",
                "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
                "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
                "/usr/bin/sshd",
                "/usr/libexec/sftp-server",
                "/usr/sbin/sshd",
                "/etc/apt",
                "/bin/bash",
                "/Library/MobileSubstrate/MobileSubstrate.dylib"
        ]
    }
}

public func getUniqueId() throws -> String{
    let userDef = UserDefaults(suiteName: "dFido2Lib_data")
    var rtn = userDef!.string(forKey: LibConfig.deviceUniqueIdKey)
    if(rtn == nil){
        rtn = UUID().uuidString
        if(nil == rtn){
            Fido2Logger.err("Cannot generate device unique id.")
            throw Fido2Error.new(error: .unknown, message: "Cannot generate device unique id.")
        }
        userDef!.set(rtn, forKey: LibConfig.deviceUniqueIdKey)
    }
    
    //For debug chnaged unique device id
    //rtn! += "c"
    
    return rtn!
}
