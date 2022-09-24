//
//  Fido2Util.swift
//  dFido2LibExt
//
//  Created by Du Qingjie on 2022/08/14.
//

import Foundation

public class Fido2Util{
    public static func getDefaultRegisterOptions(username: String, displayname: String) -> Dictionary<String, Any> {
        
        var authenticatorSelection = Dictionary<String, Any>()
        authenticatorSelection["userVerification"]="preferred"
        
        var attestationOptions = Dictionary<String, Any>()
        attestationOptions["username"] = username
        attestationOptions["displayName"] = displayname
        attestationOptions["authenticatorSelection"] = authenticatorSelection
        
        return attestationOptions
    }
    
    public static func getDefaultAuthenticateOptions(username: String = "") -> Dictionary<String, Any> {
        
        var authenticatorSelection = Dictionary<String, Any>()
        authenticatorSelection["userVerification"]="preferred"
        
        var assertionOptions = Dictionary<String, Any>()
        if (username.count > 0) {
            assertionOptions["username"] = username
        } else {
            assertionOptions["mediation"] = "conditional"
        }
        
        assertionOptions["authenticatorSelection"] = authenticatorSelection
        
        return assertionOptions
    }
}

