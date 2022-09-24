//
//  Base64.swift
//  WebAuthnKit
//
//  Created by Lyo Kato on 2018/11/20.
//  Copyright © 2018 Lyo Kato. All rights reserved.
//

import Foundation

public class Base64 {
    
    
    public static func encodeBase64(_ bytes: [UInt8]) -> String {
        return encodeBase64(Data(bytes))
    }
    
    public static func encodeBase64(_ data: Data) -> String {
        return data.base64EncodedString()
    }

    public static func encodeBase64URL(_ bytes: [UInt8]) -> String {
        return encodeBase64URL(Data(bytes))
    }

    public static func encodeBase64URL(_ str: String) -> String {
        return encodeBase64URL(Data(str.utf8))
    }
    
    public static func encodeBase64URL(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        //return data.base64EncodedString()
    }
    
    public static func decodeBase64URL(_ intext: String) -> Data? {
        var base64 = intext
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if base64.count % 4 != 0 {
            base64.append(String(repeating: "=", count: 4 - base64.count % 4))
        }
        return Data(base64Encoded: base64)
    }
    
    public static func decodeBase64URLTry(_ intext: String) -> Data? {
        var rtn = decodeBase64URL(intext)
        rtn = nil == rtn ? Data(intext.utf8) : rtn
        return rtn
    }
    
}
