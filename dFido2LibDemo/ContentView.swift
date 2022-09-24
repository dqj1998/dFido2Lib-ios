//
//  ContentView.swift
//  dFido2LibDemo
//
//  Created by Du Qingjie on 2022/08/14.
//

import SwiftUI
import dFido2LibCore
import dFido2LibExt

struct ContentView: View {
    private let fido2SvrURL = "https://mac.dqj-macpro.com" /*"http://192.168.0.124:3000"*/
    
    @State private var proceee_results:String = "---"
    @State private var username:String = ""
    @State private var displayname:String = ""
    
    var body: some View {
        VStack {
            HStack{
                Text("dFido2Lib Demo")
                    .font(.largeTitle)
                    .fontWeight(.bold)
            }
            
            HStack{
                TextField("User Name...", text: $username)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .padding()
                TextField("Display Name...", text: $displayname)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .padding()
            }
            
            Text(self.proceee_results)
                .padding()
                .font(.title)
                .frame(minHeight: 100)

            Button("Register FIDO2") {
                if !processInputs(){return}
                
                proceee_results = "Registering..."        
                Task{
                    do{
                        var opt = Fido2Util.getDefaultRegisterOptions(username: username,
                                                                      displayname: displayname)
                        
                        //Example of customizing options
                        var authenticatorSelection = opt["authenticatorSelection"] as! Dictionary<String, String>
                        authenticatorSelection.updateValue("platform", forKey: "authenticatorAttachment") //TODO: cross-platform
                        opt["authenticatorSelection"] = authenticatorSelection
                        
                        let core = Fido2Core()
                        let result = try await core.registerAuthenticator(fido2SvrURL: fido2SvrURL, username: username,
                                              displayname: displayname, attestationOptions: opt, message: "Register new authenticator")
                        if result { proceee_results = "Register succ"}
                        else { proceee_results = "Register error"}
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
                .frame(minHeight: 30)
            
            HStack{
                Button("Auth FIDO2") {
                    if !processInputs(){return}
                    
                    proceee_results = "Authenticating..."
                    Task{
                        do{
                            let opt = Fido2Util.getDefaultAuthenticateOptions(username: username)
                            
                            let core = Fido2Core()
                            let result = try await core.authenticate(fido2SvrURL: fido2SvrURL, assertionOptions: opt, message: "Authenticate yourself")
                            if result { proceee_results = "Authenticate succ"}
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
                    .frame(minHeight: 30)
                
                Button("Auth FIDO2\n(Discovery)") {
                    if Fido2Core.enabledInsideAuthenticatorResidentStorage() {
                        proceee_results = "Discovery Authenticating..."
                        Task{
                            do{
                                let opt = Fido2Util.getDefaultAuthenticateOptions()
                                
                                let core = Fido2Core()
                                let result = try await core.authenticate(fido2SvrURL: fido2SvrURL, assertionOptions: opt, message: "Authenticate yourself")
                                if result { proceee_results = "Auth Discovery succ"}
                                else { proceee_results = "Auth Discovery error"}
                            }catch{
                                Fido2Logger.err("call registerAuthenticator fail: \(error)")
                                if (((error as? Fido2Error)?.details?.localizedDescription) != nil){
                                    proceee_results = "Auth Discovery " + ((error as? Fido2Error)?.details?.localizedDescription ?? "Fido2Error details unknown")
                                } else {
                                    proceee_results = "Auth Discovery " + ((error as? Fido2Error)?.error.rawValue ?? "Fido2Error unknown")
                                }
                            }
                        }
                    } else {
                        proceee_results = "Resident storage is disabled!"
                    }
                    
                }
                
            }
            
            Text("-")
                .padding()
                .font(.title)
                .frame(minHeight: 30)
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
                    .frame(minHeight: 30)
                
                Button("Reset Lib") {
                    self.proceee_results = "Reseting..."
                    
                    Task{
                        Fido2Core.reset()
                        proceee_results = "Reset done"
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

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}


