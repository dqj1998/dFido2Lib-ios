//
//  Fido2Util.swift
//  dFido2LibExt
//
//  Created by Du Qingjie on 2022/08/14.
//

import Foundation
import dFido2LibCore

public class Fido2Util{
    public static func getDefaultRegisterOptions(username: String, displayname: String, rpId: String = "") -> Dictionary<String, Any> {
        
        var authenticatorSelection = Dictionary<String, Any>()
        authenticatorSelection["userVerification"]="preferred"
        
        var attestationOptions = Dictionary<String, Any>()
        attestationOptions["username"] = username
        attestationOptions["displayName"] = displayname
        attestationOptions["authenticatorSelection"] = authenticatorSelection
        
        if rpId.count > 0 {
            var rpOptions = Dictionary<String, Any>()
            rpOptions["id"] = rpId
            attestationOptions["rp"] = rpOptions
        }
        
        return attestationOptions
    }
    
    public static func getDefaultAuthenticateOptions(username: String = "", rpId: String = "") -> Dictionary<String, Any> {
        
        var authenticatorSelection = Dictionary<String, Any>()
        authenticatorSelection["userVerification"]="preferred"
        
        var assertionOptions = Dictionary<String, Any>()
        if (username.count > 0) {
            assertionOptions["username"] = username
        } else {
            assertionOptions["mediation"] = "conditional"
        }
        
        assertionOptions["authenticatorSelection"] = authenticatorSelection
        
        if 0 < rpId.count {
            var rpOptions = Dictionary<String, Any>()
            rpOptions["id"] = rpId
            assertionOptions["rp"] = rpOptions
        }
        
        return assertionOptions
    }
    
    public static func configAccountListExt(enable: Bool = true) {
        Fido2Core.enableAccountsList = enable
    }
}

