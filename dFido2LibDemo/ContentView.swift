//
//  ContentView.swift
//  dFido2LibDemo
//
//  Created by Du Qingjie on 2022/08/14.
//

import SwiftUI
import dFido2LibCore
import dFido2LibExt

let fido2SvrURL = "https://mac.dqj-macpro.com" /*"http://192.168.0.124:3000"*/

let rpids = ["mac.dqj-macpro.com","rp01.abc.com", "rp02.def.com"]

var cur_accounts:[String] = []
var cur_credBase64Ids:[String] = []
var user_devices:[Dictionary<String, Any>] = []
var user_devices_txt:[String] = []

struct ContentView: View {
    
    
    @State public var proceee_results:String = "---"
    @State private var inside_resident_storage:String =
        (LibConfig.enabledInsideAuthenticatorResidentStorage() ? "Enabled inside ResidentStorage" : "Disabled inside ResidentStorage")
    
    @State private var username:String = ""
    @State private var displayname:String = ""
    @State private var rpid = 0
    
    @State private var selectedAccountIndex:Int = -1
    @State private var isShowingPicker = false
    
    @State private var selectedDeviceIndex:Int = -1
    @State private var isShowingDevicesPicker = false
    
    var body: some View {
        VStack {
            VStack{
                Text("dFido2Lib Demo")
                    .font(.title)
                    .fontWeight(.bold)
                Spacer()
                Text(self.inside_resident_storage)
                    .padding()
            }
            
            VStack{
                Picker(selection: $rpid, label: Text("rpId")) {
                    ForEach(0..<rpids.count) { index in
                        Text(rpids[index])
                    }
                }.onChange(of: rpid) { tag in
                    selectedAccountIndex = -1
                    cur_accounts = []
                    cur_credBase64Ids = []
                    self.isShowingPicker=false
                }
            }
            
            HStack{
                TextField("User Name...", text: $username)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .padding()
                TextField("Display Name...", text: $displayname)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .padding()
            }
            
            DevicesPicker(selection: self.$selectedDeviceIndex, isShowing: self.$isShowingDevicesPicker, rpid: $rpid)
                            .animation(.linear)
                            .offset(y: self.isShowingDevicesPicker ? 0 : UIScreen.main.bounds.height)

            
            Text(self.proceee_results)
                .padding()
                .font(.headline)
                .frame(minHeight: 20)

            Button("Register FIDO2") {
                if !processInputs(){return}
                
                proceee_results = "Registering..."
                isShowingDevicesPicker = false
                Task{
                    do{
                        var opt = Fido2Util.getDefaultRegisterOptions(username: username,
                                                                      displayname: displayname, rpId: rpids[rpid])
                        
                        //Example of customizing options
                        var authenticatorSelection = opt["authenticatorSelection"] as! Dictionary<String, String>
                        authenticatorSelection.updateValue("platform", forKey: "authenticatorAttachment") //TODO: cross-platform
                        opt["authenticatorSelection"] = authenticatorSelection
                        
                        let core = Fido2Core()
                        let result = try await core.registerAuthenticator(fido2SvrURL: fido2SvrURL, attestationOptions: opt,
                                                                          message: "Register new authenticator")
                        if result {
                            proceee_results = "Register succ"
                            try await loadUserDevices(core: core, rpId: rpids[rpid])
                            isShowingDevicesPicker = true
                        } else { proceee_results = "Register error"}
                    }catch{
                        Fido2Logger.err("call registerAuthenticator fail: \(error)")
                        if (((error as? Fido2Error)?.details?.localizedDescription) != nil){
                            proceee_results = "Register " + ((error as? Fido2Error)?.details?.localizedDescription ?? "Fido2Error details unknown")
                        } else {
                            proceee_results = "Register " + ((error as? Fido2Error)?.error.rawValue ?? "Fido2Error unknown")
                        }
                    }
                }
                
            }
            
            Text("-")
                .padding()
                .font(.title)
                .frame(minHeight: 10)
            
            HStack{
                Button("Auth FIDO2") {
                    if !processInputs(){return}
                    
                    proceee_results = "Authenticating..."
                    isShowingDevicesPicker = false
                    Task{
                        do{
                            let opt = Fido2Util.getDefaultAuthenticateOptions(username: username, rpId: rpids[rpid])
                            
                            let core = Fido2Core()
                            let result = try await core.authenticate(fido2SvrURL: fido2SvrURL, assertionOptions: opt, message: "Authenticate yourself", nil)
                            if result {
                                //Load devices
                                try await loadUserDevices(core: core, rpId: rpids[rpid])
                                isShowingDevicesPicker = true
                                proceee_results = "Authenticate succ"
                            }
                            else { proceee_results = "Authenticate error"}
                        }catch{
                            Fido2Logger.err("call registerAuthenticator fail: \(error)")
                            if (((error as? Fido2Error)?.details?.localizedDescription) != nil){
                                proceee_results = "Authenticate " + ((error as? Fido2Error)?.details?.localizedDescription ?? "Fido2Error details unknown")
                            } else {
                                proceee_results = "Authenticate " + ((error as? Fido2Error)?.error.rawValue ?? "Fido2Error unknown")
                            }
                        }
                    }
                    
                }
                
                Text("|")
                    .padding()
                    .font(.title)
                    .frame(minHeight: 10)
                
                ZStack {
                    Button("Auth FIDO2\n(Discovery)") {
                        var accCount = 0
                        if Fido2Core.enableAccountsList {
                            let accounts = dFido2ClientExt.listAccounts(rpId: rpids[rpid])
                            if nil != accounts && (accounts!.accounts.count > 1){
                                accCount = accounts!.accounts.count
                                Fido2Logger.debug("Count:" + String(accounts!.accounts.count))
                                cur_accounts=[]; cur_credBase64Ids=[]
                                for acc in accounts!.accounts {
                                    var name = acc.displayname
                                    if name.isEmpty
                                    {
                                        name = acc.username
                                    }
                                    cur_accounts.append(name)
                                    cur_credBase64Ids.append(acc.credIdBase64)
                                }
                                
                                self.isShowingPicker=true
                            }
                        }
                        
                        if 0==accCount {
                            Task{
                                proceee_results = await authDiscover(rpId: rpids[rpid], selectedAccountIndex: -1)
                            }
                        }
                    }
                    
                    AccountPicker(selection: self.$selectedAccountIndex, isShowing: self.$isShowingPicker,
                                  proceee_results: self.$proceee_results, rpid: $rpid)
                                    .animation(.linear)
                                    .offset(y: self.isShowingPicker ? 0 : UIScreen.main.bounds.height)
                }
            }
            
            Text("-")
                .padding()
                .font(.title)
                .frame(minHeight: 10)
            
            HStack{
                Button("Clear keys") {
                    self.proceee_results = "Clearing..."
                    
                    Task{
                        Fido2Core.clearKeys()
                        proceee_results = "Clear done"
                    }
                    
                }
            
                Text("|")
                    .padding()
                    .font(.title)
                    .frame(minHeight: 10)
                
                Button("Reset Lib") {
                    self.proceee_results = "Reseting..."
                    
                    Task{
                        Fido2Core.reset()
                        proceee_results = "Reset done"
                        
                    inside_resident_storage =
                        (LibConfig.enabledInsideAuthenticatorResidentStorage() ? "Enabled inside ResidentStorage" : "Disabled inside ResidentStorage")
                    }
                }
                
                Text("|")
                    .padding()
                    .font(.title)
                    .frame(minHeight: 10)
                
                Button("Clear RP") {
                    Task{
                        Fido2Core.clearKeys(rpId: rpids[rpid])
                        proceee_results = "Clear rp done"
                    }
                }
            }
        }
        .padding()
    }
    
    private func processInputs() -> Bool{
        if username.isEmpty {
            proceee_results = "Input user name, please."
            displayname = ""
            return false
        }
        if displayname.isEmpty {
            displayname = "Display_" + username
        }
        return true
    }
    
    
}

public func authDiscover(rpId: String, selectedAccountIndex: Int) async -> String {
    var rtn = ""
    if LibConfig.enabledInsideAuthenticatorResidentStorage() {
            do{
                let opt = Fido2Util.getDefaultAuthenticateOptions(rpId: rpId)
                
                let core = Fido2Core()
                var credId:Data?
                if 0<=selectedAccountIndex {
                    credId = Base64.decodeBase64URL(cur_credBase64Ids[selectedAccountIndex])!
                }
                let result = try await core.authenticate(fido2SvrURL: fido2SvrURL, assertionOptions: opt, message: "Authenticate yourself", credId?.encodedHexadecimals)
                if result {
                    rtn = "Auth Discovery succ"
                }
                else { rtn = "Auth Discovery error"}
            }catch{
                Fido2Logger.err("call registerAuthenticator fail: \(error)")
                if (((error as? Fido2Error)?.details?.localizedDescription) != nil){
                    rtn = "Auth Discovery " + ((error as? Fido2Error)?.details?.localizedDescription ?? "Fido2Error details unknown")
                } else {
                    rtn = "Auth Discovery " + ((error as? Fido2Error)?.error.rawValue ?? "Fido2Error unknown")
                }
            }
        
    } else {
        rtn = "Resident storage is disabled!"
    }
    
    return rtn
}

func loadUserDevices(core: Fido2Core, rpId: String) async throws{
    user_devices = try await core.listUserDevices(fido2SvrURL: fido2SvrURL, rpId: rpId)
    user_devices_txt = []
    for index in 0..<user_devices.count {
        if(nil == user_devices[index]["desc"] || (user_devices[index]["desc"] as! String).utf8.count == 0){
            user_devices_txt.append(user_devices[index]["userAgent"] as! String)
        }else{
            user_devices_txt.append(user_devices[index]["desc"] as! String)
        }
    }
}

struct AccountPicker: View {
    @Binding var selection: Int
    @Binding var isShowing: Bool
    @Binding var proceee_results: String
    @Binding var rpid: Int
    var body: some View {
        VStack {
            Spacer()
            Button(action: {
                self.isShowing = false
            }) {
                /*HStack {
                    Spacer()
                    Text("Close").padding(.horizontal, 16)
                }*/
            }
            
            Picker(selection: $selection, label: Text("")) {
                Text("Please select user account").tag(-1)
                ForEach(0..<cur_accounts.count, id: \.self) { index in
                    Text(cur_accounts[index]).tag(index)
                }
            }
            .frame(width: 200)
            .labelsHidden()
            .onChange(of: selection) { tag in
                if -1 != tag {
                    proceee_results = "Discovery Authenticating..."
                    Task{
                        proceee_results = await authDiscover(rpId: rpids[rpid], selectedAccountIndex: tag)
                    }
                }
            }
        }
    }
}

struct DevicesPicker: View {
    @Binding var selection: Int
    @Binding var isShowing: Bool
    @Binding var rpid: Int
    
    var body: some View {
        VStack {
            Spacer()
            Button(action: {
                self.isShowing = false
            }) {
                /*HStack {
                    Spacer()
                    Text("Close").padding(.horizontal, 16)
                }*/
            }
            
            Picker(selection: $selection, label: Text("")) {
                Text("User devices").tag(-1)
                ForEach(0..<user_devices.count, id: \.self) { index in
                    Text(user_devices_txt[index]).tag(index)
                }
            }
            .frame(width: 300)
            .labelsHidden()
            .onChange(of: selection) { tag in
                if -1 != tag {
                    let core = Fido2Core()
                    Task{
                        //del device
                        let result = try await core.delUserDevice(fido2SvrURL: fido2SvrURL, deviceId: user_devices[tag]["device_id"] as! Int, rpId: rpids[rpid])
                        if(result){
                            user_devices.remove(at: tag)
                            self.isShowing = false
                            self.isShowing = true
                        }
                    }
                }
            }
        }
    }
}


struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}


