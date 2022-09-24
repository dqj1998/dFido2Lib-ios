//
//  LibConfig.swift
//  dFido2LibCore
//
//  Created by Du Qingjie on 2022/08/21.
//

import Foundation

public class LibConfig{
    public static var aaguid: [UInt8] = UUIDHelper.zeroBytes
    
    public func enableDebugLog(){
        Fido2Logger.enable_debug = true;
    }
    
    public func disableDebugLog(){
        Fido2Logger.enable_debug = false;
    }
    
    
}
