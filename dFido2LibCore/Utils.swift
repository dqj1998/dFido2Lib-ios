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
    var encodedHexadecimals: [UInt8] {
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
