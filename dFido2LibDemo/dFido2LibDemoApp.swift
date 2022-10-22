//
//  dFido2LibDemoApp.swift
//  dFido2LibDemo
//
//  Created by Du Qingjie on 2022/08/14.
//

import SwiftUI
import dFido2LibCore

@main
struct dFido2LibDemoApp: App {
    init() {
        Fido2Logger.enable_debug = true
        //Fido2Core.configInsideAuthenticatorResidentStorage(enable: false)
    }
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
