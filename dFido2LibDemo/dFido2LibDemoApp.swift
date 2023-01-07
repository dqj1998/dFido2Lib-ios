//
//  dFido2LibDemoApp.swift
//  dFido2LibDemo
//
//  Created by Du Qingjie on 2022/08/14.
//

import SwiftUI
import dFido2LibCore
import dFido2LibExt

@main
struct dFido2LibDemoApp: App {
    init() {
        LibConfig.enableDebugLog()
        LibConfig.configAccountListExt(enable: true)
        
        //LibConfig.configInsideAuthenticatorResidentStorage(enable: false)
        
        //Configs for enterprise attestation
        ///16 char, Cannot double with aaguids in FIDO2 meta data(https://mds3.fidoalliance.org/)
        ///Have to register ENTERPRISE_RPs and ENTERPRISE_AAGUIDs in fido2-node server env file
        ///Changing to an unregistered aaguid will get error of registration.
        LibConfig.setPlatformAuthenticatorAAGUID(aaguid: "aaguid_rp01_0000")
        
        LibConfig.addEnterpriseRPIds(ids: ["rp01.abc.com", "rp02.def.com"])
    }
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
