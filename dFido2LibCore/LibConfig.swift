//
//  LibConfig.swift
//  dFido2LibCore
//
//  Created by Du Qingjie on 2022/08/21.
//

import Foundation

public class LibConfig{
    public static let deviceUniqueIdKey: String = "dfido2_device_unique_id"
    
    public static var aaguid: [UInt8] = UUIDHelper.zeroBytes
    
    public static var enterpriseRPIds: [String] = []
    
    public static var enableJailBroken: Bool = false
    
    public static var allowPasskeyMultipleRegistration: Bool = false
    
    public static var deviceName: String = "dFido2Lib-iOS" //Device name on user's device list
    
    public static func enableDebugLog(){
        Fido2Logger.enable_debug = true;
    }
    
    public static func disableDebugLog(){
        Fido2Logger.enable_debug = false;
    }
    
    public static func configAccountListExt(enable: Bool = true) {
        Fido2Core.enableAccountsList = enable
    }
    
    public static func addEnterpriseRPIds(ids: [String]) {
        enterpriseRPIds += ids
    }
    
    /*
     Must wait for the timeout before sending excaption when cannot find authenticator according to the FIDO2 spec.
     You can enable/disable this feature.
     Default is enabled
     But be careful, disabling this feature may decrease the security level.
     */
    public static func configExcaptionTimeoutWaiting(enable: Bool){
        Fido2Core.waitCannotFindAuthenticatorTimeout = enable
    }
    
    /*
    Enable = Can register one device as mutiple authenticators through differet transports
    Default is false
    Refer spec 5.1.3 - 20.7: For each credential descriptor C in options.excludeCredentials
    */
    public static func configMultipleCredByMultipleTransports(enable: Bool){
        Fido2Core.canRegisterMultipleCredByMultipleTransports = enable
    }
    
    /*
     Config if the inside authenticator storage resident keys.
     Default is enabled.
     */
    public static func configInsideAuthenticatorResidentStorage(enable: Bool){
        PlatformAuthenticator.enableResidentStorage = enable
        if !enable {
            PlatformAuthenticator.enableSilentCredentialDiscovery = false
            Fido2Logger.info("Auto disabled inside authenticator SilentCredentialDiscovery.")
        }
    }
    
    public static func enabledInsideAuthenticatorResidentStorage() -> Bool{
        return PlatformAuthenticator.enableResidentStorage
    }
    
    /*
     Config if the inside authenticator can SilentCredentialDiscovery.
     Default is enabled.
     */
    public static func configInsideAuthenticatorSilentCredentialDiscovery(enable: Bool){
        PlatformAuthenticator.enableSilentCredentialDiscovery = enable
        if enable {
            PlatformAuthenticator.enableResidentStorage = true
            Fido2Logger.info("Auto enabled inside authenticator ResidentStorage.")
        }
    }
    
    /*
     Set internal platform authenticator
     Normally this is for enterprise attention
     */
    public static func setPlatformAuthenticatorAAGUID(aaguid:String){
        LibConfig.aaguid = readHexString(hexString: aaguid) //Array(aaguid.utf8)
    }
    
    static func readHexString(hexString: String) -> [UInt8]{
        let length = hexString.count / 2
        var byteArray = [UInt8](repeating: 0, count: length)

        for i in 0..<length {
            let startIndex = hexString.index(hexString.startIndex, offsetBy: i*2)
            let endIndex = hexString.index(startIndex, offsetBy: 2)
            let subString = hexString[startIndex..<endIndex]
            byteArray[i] = UInt8(subString, radix: 16)!
        }
        return byteArray
    }
}
