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
        LibConfig.enableJailBroken = true //For development, comment out for product!
        
        LibConfig.enableDebugLog()
        LibConfig.configAccountListExt(enable: true)
        
        //LibConfig.configInsideAuthenticatorResidentStorage(enable: false)
        
        //Configs for enterprise attestation
        ///16 char, Cannot double with aaguids in FIDO2 meta data(https://mds3.fidoalliance.org/)
        ///Have to set enterprise to true and set enterprise_aaguids in doamn.json on server
        ///Changing to an unregistered aaguid will get error of registration.
        LibConfig.setPlatformAuthenticatorAAGUID(aaguid: "aaguid_test_0000")
        
        LibConfig.addEnterpriseRPIds(ids: ["rp01.abc.com", "rp02.def.com"])
    }
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
