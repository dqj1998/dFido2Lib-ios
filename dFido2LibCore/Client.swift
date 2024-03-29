//
//  Fido2Core.swift
//  dfido2fw
//
//  Created by Du Qingjie on 2022/08/13.
//

import Foundation
import UIKit
import CryptoKit
import SwiftUI
import AuthenticationServices
import LocalAuthentication

private var sessionId: String = ""

public class Fido2Core{
    public let defaultTimeout: Double = 2 * 60
    public let minTimeout: Double = 1
    public let maxTimeout: Double = 30 * 60
    
    private var curTimeout: Double
    private var processTimeout: Bool = false;
    private var processTimer: Timer?
    
    private var startTime: Double?
    
    public static var waitCannotFindAuthenticatorTimeout:Bool = true
    
    public static var canRegisterMultipleCredByMultipleTransports: Bool = false
    
    private let authenticatorPlatform: PlatformAuthenticator = PlatformAuthenticator()
    
    public static var enableAccountsList: Bool = false
    
    public static var AccountsKeyId: String = "dFido2Lib_client_accounts"
    
    //var authenticationAnchor: ASPresentationAnchor?
    
    public init() {
        self.curTimeout = self.defaultTimeout
    }
    
    public static func reset(){
        Fido2Core.waitCannotFindAuthenticatorTimeout = true
        Fido2Core.canRegisterMultipleCredByMultipleTransports = false
        
        PlatformAuthenticator.enableResidentStorage = true
        PlatformAuthenticator.enableSilentCredentialDiscovery = true
        _ = PlatformAuthenticator.reset()
        
        try? KeyTools.clearKey(keyChainIdPrefix: Fido2Core.AccountsKeyId)
        
        //Client cannot reset/clear server-side according to WebAuthN spec.
        //Server can clear based on users' operation or inactivity check.
        //We may add some ext methods to support client-side management
    }
    
    public static func clearKeys(rpId:String=""){
        _ = PlatformAuthenticator.clearKeys(rpId:rpId)
        try? KeyTools.clearKey(keyChainIdPrefix: Fido2Core.AccountsKeyId, handle: rpId)
    }
    
    //dqj TODO: cancel method(6.3.4. The authenticatorCancel Operation)
    
    public func registerAuthenticator(fido2SvrURL:String,
                                      attestationOptions: Dictionary<String, Any>,
                                      message: String //,anchor: ASPresentationAnchor
                        ) async throws -> Bool {
        var rtn=false;
        
        do {
            try checkDevice()
            
            self.startTime = Date().timeIntervalSince1970
            self.processTimeout = false
            if nil != self.processTimer {
                self.processTimer!.invalidate()
            }
            
            sessionId = ""
            
            let jsonData = try JSONSerialization.data(withJSONObject: attestationOptions)
            var jsonStr = String(bytes: jsonData, encoding: .utf8)!
            Fido2Logger.debug("</attestation/options> req: \(jsonStr)")
            
            let rpDomain = (attestationOptions["rp"] as! Dictionary<String, Any>)["id"] as! String
            let origURL = "https://"+rpDomain
            let headers = ["User-Agent":LibConfig.deviceName, "referer": origURL]
            
            let optsData = try await httpRequest(url: fido2SvrURL+"/attestation/options", method: "POST",
                                                 body: jsonStr.data(using: .utf8)!, headers: headers,
                                                 cachePolicy: URLRequest.CachePolicy.reloadIgnoringLocalAndRemoteCacheData)
            let jsonOptsData = try JSONSerialization.jsonObject(with: optsData, options: []) as? [String: Any]
            Fido2Logger.debug("</attestation/options> resp text: \(String(describing: jsonOptsData))")
            
            let pubkCredCrtOpts = try JSONDecoder().decode(PublicKeyCredentialCreationOptions.self, from:optsData)
            Fido2Logger.debug("</attestation/options> resp: \(pubkCredCrtOpts)")
            
            var pubkeyCred: PublicKeyCredential<AuthenticatorAttestationResponse>;
            //Check if can use Passkey
            if((jsonOptsData?["extensions"] != nil) && (jsonOptsData?["extensions"] as! Dictionary<String, Any>)["passkeySync"] != nil &&
                    (jsonOptsData?["extensions"] as! Dictionary<String, Any>)["passkeySync"] as! Bool){
                let authMgr = AuthorizationManager()
                do{
                    let regResult = try await authMgr.startRegistration(rpDomain: rpDomain, pubkeyCredOpts: pubkCredCrtOpts, allowMultipleRegistration: LibConfig.allowPasskeyMultipleRegistration)
                
                    Fido2Logger.debug("Passkey reg resp: \(regResult)")
                    
                    let response = AuthenticatorAttestationResponse(
                        clientDataJSON:    Base64.encodeBase64URL(regResult.rawClientDataJSON),
                        attestationObject: Base64.encodeBase64URL(regResult.rawAttestationObject!)
                        //dqj TODO: support [[transports]]
                    )
                    
                    pubkeyCred = PublicKeyCredential<AuthenticatorAttestationResponse>(
                        rawId:  Base64.encodeBase64URL(regResult.credentialID),
                        id:     Base64.encodeBase64URL(regResult.credentialID),
                        response: response
                    )
                }catch{
                    if(error is Fido2Error){
                        Fido2Logger.err("call startRegistration with Passkey fail: \((error as! Fido2Error).error):\(error.localizedDescription)")
                        throw error
                    }else{
                        Fido2Logger.err("call startRegistration with Passkey fail: \(error):\(error.localizedDescription)")
                        throw Fido2Error.new(error: .unknown, message: error.localizedDescription)
                    }
                    
                }
            }else{
                pubkeyCred = try await self.createNewCredential(options: pubkCredCrtOpts, origin: origURL, message: message)
            }
            
            jsonStr = pubkeyCred.toJSON() ?? ""
            Fido2Logger.debug("</attestation/result> req: \(jsonStr)")
            
            var attResult: Data
            do{
                attResult = try await httpRequest(url: fido2SvrURL+"/attestation/result", method: "POST",
                                                     body: jsonStr.data(using: .utf8)!, headers: headers,
                                                      cachePolicy: URLRequest.CachePolicy.reloadIgnoringLocalAndRemoteCacheData, timeout: curTimeout)
            }catch{
                Fido2Logger.err("</attestation/result> http exception \(error)")
                throw Fido2Error.new(error: .unknown, message: error.localizedDescription)
            }
            
            guard let rsltStr = String(data: attResult, encoding: .utf8) else {
                Fido2Logger.err("failed to parse attResult")
                throw Fido2Error(error: .badData)
            }
            Fido2Logger.debug("</attestation/result> resp: \(rsltStr)")
            
            if self.processTimeout {
                Fido2Logger.debug("<registerAuthenticator> already timeout")
                throw Fido2Error(error: .timeout)
            }
            
            if !rsltStr.isEmpty {
                if let rep = try JSONSerialization.jsonObject(with: rsltStr.data(using: String.Encoding.utf8)!, options: []) as? [String: Any] {
                    rtn = nil != rep["status"] && (rep["status"] as! String).uppercased() == "OK"
                    sessionId = rep["session"] as? String ?? ""
                    
                    if rtn && Fido2Core.enableAccountsList{
                        let rp = pubkCredCrtOpts.rp.id ?? pubkCredCrtOpts.rp.name
                        let acc = Account(rpid: rp, username: pubkCredCrtOpts.user.name, displayname: pubkCredCrtOpts.user.displayName, credIdBase64: pubkeyCred.id)
                        let accounts = try? KeyTools.retrieveKey(keyChainId: Fido2Core.AccountsKeyId, handle: rp)
                        if nil == accounts{
                            let new_accounts = Accounts(accounts: [acc])
                            try? KeyTools.saveKey(keyChainId: Fido2Core.AccountsKeyId, handle: rp, key: Data(new_accounts.toJSON()!.utf8))
                        }else{
                            var cur_accounts = Accounts.fromJSON(json: String(data: accounts!, encoding: .utf8)!)
                            if nil != cur_accounts{
                                cur_accounts!.accounts.append(acc)
                                try? KeyTools.saveKey(keyChainId: Fido2Core.AccountsKeyId, handle: rp, key: Data(cur_accounts!.toJSON()!.utf8))
                            }else{
                                Fido2Logger.err("Accounts.fromJSON is nil.")
                            }
                        }
                    }
                    
                    if !rtn && !LibConfig.enabledInsideAuthenticatorResidentStorage() {
                        Fido2Logger.err("Most like your FIDO2 server does not really support non-resident Credentials, if you confirmed all other cases.")
                    }
                } else {
                    Fido2Logger.err("registerAuthenticator: parse </attestation/result> resp fail.")
                }
            } else {
                Fido2Logger.err("registerAuthenticator: </attestation/result> resp empty.")
            }
            
        } catch {
            Fido2Logger.err("registerAuthenticator fail: \(error)")
            throw error
        }
        
        return rtn;
    }
    
    public func authenticate(fido2SvrURL:String, assertionOptions: Dictionary<String, Any>,
                             message: String, _ selectedCredId:[UInt8]?
                        ) async throws -> Bool {
        var rtn=false;
        
        do{
            try checkDevice()
            
            self.startTime = Date().timeIntervalSince1970
            self.processTimeout = false
            if nil != self.processTimer {
                self.processTimer!.invalidate()
            }
            
            sessionId = ""
            
            let jsonData = try JSONSerialization.data(withJSONObject: assertionOptions)
            var jsonStr = String(bytes: jsonData, encoding: .utf8)!
            Fido2Logger.debug("</assertion/options> req: \(jsonStr)")
            
            let rpDomain = (assertionOptions["rp"] as! Dictionary<String, Any>)["id"] as! String
            let origURL = "https://"+rpDomain
            let headers = ["User-Agent":LibConfig.deviceName, "referer": origURL]
            
            let optsData = try await httpRequest(url: fido2SvrURL+"/assertion/options", method: "POST",
                                                 body: jsonStr.data(using: .utf8)!, headers: headers,
                                                 cachePolicy: URLRequest.CachePolicy.reloadIgnoringLocalAndRemoteCacheData)
            let jsonOptsData = try JSONSerialization.jsonObject(with: optsData, options: []) as? [String: Any]
            Fido2Logger.debug("</assertion/options> resp text: \(String(describing: jsonOptsData))")
            
            if ((jsonOptsData?["challenge"]) == nil)  {
                throw Fido2Error.new(error: .unknown, message: jsonOptsData?["message"] as? String )
            }
                
            var pubkCredReqOpts = try JSONDecoder().decode(PublicKeyCredentialRequestOptions.self, from:optsData)
            Fido2Logger.debug("</assertion/options> resp: \(pubkCredReqOpts)")
            
            //TODO: Support cross-platform authenocator
            if nil != assertionOptions["mediation"] {
                pubkCredReqOpts.mediation = CredentialMediationRequirement(rawValue: assertionOptions["mediation"] as! String)
            }
            
            if nil == pubkCredReqOpts.rpId && nil != assertionOptions["rp"] && nil != (assertionOptions["rp"] as! Dictionary<String, Any>)["id"] {
                pubkCredReqOpts.rpId = (assertionOptions["rp"] as! Dictionary<String, Any>)["id"] as! String?
            }
            
            var pubkeyCred:PublicKeyCredential<AuthenticatorAssertionResponse>;
            //Check if can use Passkey
            if((jsonOptsData?["extensions"] != nil) && (jsonOptsData?["extensions"] as! Dictionary<String, Any>)["passkeySync"] != nil &&
                    (jsonOptsData?["extensions"] as! Dictionary<String, Any>)["passkeySync"] as! Bool){
                let challenge = (jsonOptsData?["challenge"] as! String).data(using: .utf8)
                let authMgr = AuthorizationManager()
                do{
                    let authResult = try await authMgr.startAuthentication(rpDomain: rpDomain, challenge: challenge!)
                
                    Fido2Logger.debug("Passkey auth resp: \(authResult)")
                
                    let response = AuthenticatorAssertionResponse(
                        clientDataJSON:    Base64.encodeBase64URL(authResult.rawClientDataJSON),
                        authenticatorData: Base64.encodeBase64URL(authResult.rawAuthenticatorData),
                        signature:         Base64.encodeBase64URL(authResult.signature),
                        userHandle:        Base64.encodeBase64URL(authResult.userID)
                        //dqj TODO: support [[transports]]
                    )
                    
                    pubkeyCred = PublicKeyCredential<AuthenticatorAssertionResponse>(
                        rawId:  Base64.encodeBase64URL(authResult.credentialID),
                        id:     Base64.encodeBase64URL(authResult.credentialID),
                        response: response
                    )
                }catch{
                    Fido2Logger.err("call startAuthentication with Passkey fail: \(error)")
                    throw Fido2Error.new(error: .unknown, message: error.localizedDescription)
                }
            }else{
                pubkeyCred = try await self.discoverFromExternalSource(options: pubkCredReqOpts, origin: origURL, message: message,
                                                                           selectedCredId: selectedCredId)
            }
            jsonStr = pubkeyCred.toJSON() ?? ""
            Fido2Logger.debug("</assertion/result> req: \(jsonStr)")
            
            var assResult: Data
            do{
                assResult = try await httpRequest(url: fido2SvrURL+"/assertion/result", method: "POST",
                                                     body: jsonStr.data(using: .utf8)!, headers: headers,
                                                      cachePolicy: URLRequest.CachePolicy.reloadIgnoringLocalAndRemoteCacheData, timeout: curTimeout)
            }catch{
                Fido2Logger.debug("</assertion/result> http exception \(error)")
                throw Fido2Error.new(error: .unknown, details: error)
            }
            
            guard let rsltStr = String(data: assResult, encoding: .utf8) else {
                Fido2Logger.err("failed to parse assResult")
                throw Fido2Error(error: .badData)
            }
            Fido2Logger.debug("</assertion/result> resp: \(rsltStr)")
            
            let resp=try JSONSerialization.jsonObject(with: rsltStr.data(using: String.Encoding.utf8)!, options: []) as? [String: Any]
            
            if self.processTimeout {
                Fido2Logger.debug("<authenticate> already timeout")
                throw Fido2Error(error: .timeout)
            }
            
            if(nil != resp && resp!["status"] != nil && (resp!["status"] as! String).uppercased()=="OK"){
                sessionId = resp!["session"] != nil ? resp!["session"] as! String:""
                rtn = true
            }
            
        } catch {
            Fido2Logger.err("Authentication fail: \(error)")
            throw error
        }
        
        return rtn
    }
    
    //TODO: Process recovery links
    
    public func listUserDevices(fido2SvrURL:String, rpId: String) async throws -> [Dictionary<String, Any>] {
        var rtn = [Dictionary<String, Any>]()
        do{
            try checkDevice()
            
            if(try await !validSession(fido2SvrURL: fido2SvrURL, rpId: rpId)){
                Fido2Logger.debug("<listUserDevices> no user session, have to authenticate first.")
                throw Fido2Error.new(error: .unknown, message: "<listUserDevices> no user session, have to authenticate first.")
            }
            
            var reqDic = Dictionary<String, Any>()
            reqDic["session"]=sessionId
            var rpOptions = Dictionary<String, Any>()
            rpOptions["id"] = rpId
            reqDic["rp"] = rpOptions
            
            let jsonData = try JSONSerialization.data(withJSONObject: reqDic)
            let jsonStr = String(bytes: jsonData, encoding: .utf8)!
            Fido2Logger.debug("<listUserDevices> req: \(jsonStr)")
            
            let headers = ["User-Agent":LibConfig.deviceName]
            
            let respData = try await httpRequest(url: fido2SvrURL+"/usr/dvs/lst", method: "POST",
                                                 body: jsonStr.data(using: .utf8)!, headers: headers,
                                                 cachePolicy: URLRequest.CachePolicy.reloadIgnoringLocalAndRemoteCacheData)
            let respJsonData = try JSONSerialization.jsonObject(with: respData, options: []) as? [String: Any]
            Fido2Logger.debug("<listUserDevices> resp text: \(String(describing: respJsonData))")
            
            if(nil != respJsonData && respJsonData!["status"] != nil && (respJsonData!["status"] as! String).uppercased()=="OK" &&
                    respJsonData?["session"] as! String == sessionId){
                rtn.append(contentsOf: (respJsonData?["devices"] as! [Dictionary<String, Any>]))                
            } else {
                throw Fido2Error.new(error: .unknown, message: respJsonData?["errorMessage"] as? String)
            }
        } catch {
            Fido2Logger.err("listUserDevices fail: \(error)")
            throw error
        }
        return rtn;
    }
    
    public func delUserDevice(fido2SvrURL:String, deviceId: Int, rpId: String) async throws -> Bool {
        var rtn = false
        do{
            try checkDevice()
            
            if(try await !validSession(fido2SvrURL: fido2SvrURL, rpId: rpId)){
                Fido2Logger.debug("<delUserDevice> no user session, have to authenticate first.")
                throw Fido2Error.new(error: .unknown, message: "<delUserDevice> no user session, have to authenticate first.")
            }
            
            var reqDic = Dictionary<String, Any>()
            reqDic["session"]=sessionId
            var rpOptions = Dictionary<String, Any>()
            rpOptions["id"] = rpId
            reqDic["rp"] = rpOptions
            reqDic["device_id"]=deviceId
            
            let jsonData = try JSONSerialization.data(withJSONObject: reqDic)
            let jsonStr = String(bytes: jsonData, encoding: .utf8)!
            Fido2Logger.debug("<delUserDevice> req: \(jsonStr)")
            
            let headers = ["User-Agent":LibConfig.deviceName]
            
            let respData = try await httpRequest(url: fido2SvrURL+"/usr/dvs/rm", method: "POST",
                                                 body: jsonStr.data(using: .utf8)!, headers: headers,
                                                 cachePolicy: URLRequest.CachePolicy.reloadIgnoringLocalAndRemoteCacheData)
            let respJsonData = try JSONSerialization.jsonObject(with: respData, options: []) as? [String: Any]
            Fido2Logger.debug("<delUserDevice> resp text: \(String(describing: respJsonData))")
            
            if(nil != respJsonData && respJsonData!["status"] != nil && (respJsonData!["status"] as! String).uppercased()=="OK" &&
                    respJsonData?["session"] as! String == sessionId){
                rtn = true
            } else {
                throw Fido2Error.new(error: .unknown, message: respJsonData?["errorMessage"] as? String)
            }
        } catch {
            Fido2Logger.err("delUserDevice fail: \(error)")
            throw error
        }
        return rtn;
    }
    
    public func getRegistrationUser(fido2SvrURL:String, regSessionId: String) async throws -> String {        
        var rtn="";
        
        do{
            
            var reqDic = Dictionary<String, Any>()
            reqDic["session_id"]=regSessionId
            
            let jsonData = try JSONSerialization.data(withJSONObject: reqDic)
            let jsonStr = String(bytes: jsonData, encoding: .utf8)!
            Fido2Logger.debug("<getRegistrationUser> req: \(jsonStr)")
            
            let headers = ["User-Agent":LibConfig.deviceName]
            
            let respData = try await httpRequest(url: fido2SvrURL+"/reg/username", method: "POST",
                                                 body: jsonStr.data(using: .utf8)!, headers: headers,
                                                 cachePolicy: URLRequest.CachePolicy.reloadIgnoringLocalAndRemoteCacheData)
            let respJsonData = try JSONSerialization.jsonObject(with: respData, options: []) as? [String: Any]
            Fido2Logger.debug("<getRegistrationUser> resp text: \(String(describing: respJsonData))")
            
            if((respJsonData?["status"] as! String).uppercased() == "OK"){
                rtn = respJsonData?["username"] as! String
            }
            
        } catch {
            Fido2Logger.err("getRegistrationUser fail: \(error)")
            throw error
        }
        
        return rtn
    }
    
    public func logoutFido2UserSession(){
        sessionId = ""
    }
    
    public func validSession(fido2SvrURL:String, rpId: String) async throws -> Bool {
        if(sessionId.isEmpty){
            return false;
        }
        
        var rtn=false;
        
        do{
            
            var reqDic = Dictionary<String, Any>()
            reqDic["session"]=sessionId
            var rpOptions = Dictionary<String, Any>()
            rpOptions["id"] = rpId
            reqDic["rp"] = rpOptions
            
            let jsonData = try JSONSerialization.data(withJSONObject: reqDic)
            var jsonStr = String(bytes: jsonData, encoding: .utf8)!
            Fido2Logger.debug("<validSession> req: \(jsonStr)")
            
            let headers = ["User-Agent":LibConfig.deviceName]
            
            let respData = try await httpRequest(url: fido2SvrURL+"/usr/validsession", method: "POST",
                                                 body: jsonStr.data(using: .utf8)!, headers: headers,
                                                 cachePolicy: URLRequest.CachePolicy.reloadIgnoringLocalAndRemoteCacheData)
            let respJsonData = try JSONSerialization.jsonObject(with: respData, options: []) as? [String: Any]
            Fido2Logger.debug("<validSession> resp text: \(String(describing: respJsonData))")
            
            rtn = (respJsonData?["status"] as! String).uppercased() == "OK"
            
        } catch {
            Fido2Logger.err("validSession fail: \(error)")
            throw error
        }
        
        return rtn
    }
    
    /// Registration methods
    /// https://w3c.github.io/webauthn/#sctn-createCredential
    private func createNewCredential(options: PublicKeyCredentialCreationOptions, origin: String, message: String) async throws -> PublicKeyCredential<AuthenticatorAttestationResponse> {

        // 5.1.3 1-3 and 6-7: No need as a lib
        
        // 5.1.3 - 4
        curTimeout = self.adjustLifetimeTimer(timeout: options.timeout ?? 0, userVerification: options.authenticatorSelection?.userVerification ?? .discouraged)
        
        // 5.1.3 - 5
        let idCount = options.user.id.utf8.count
        if 1 > idCount || 64 < idCount {
            throw Fido2Error(error: .typeError)
        }
        
        // 5.1.3 - 8
        let rpId = self.pickRelyingPartyID(rpId: options.rp.id, origin: origin)
                
        // 5.1.3 - 9,10
        // check options.pubKeyCredParmas
        // currently 'public-key' is only in specification.
        // do nothing

        // TODO Extension handling
        // 5.1.3 - 11
        // 5.1.3 - 12

        // 5.1.3 - 13,14,15 Prepare ClientData, JSON, Hash
        let (_, clientDataJSON, clientDataHash) =
            self.generateClientData(
                type:      .webAuthnCreate,
                challenge: options.challenge,
                origin: origin
            )
        
        // 5.1.3 - 17 : dqj TODO: authenticators collection - support issuedRequests
        
        // 5.1.3 - 18 : dqj TODO: authenticators collection - support set of authenticators
        let authenticators = [authenticatorPlatform]
        
        // 5.1.3 - 19 Start lifetimeTimer.
        processTimer = Timer.scheduledTimer(withTimeInterval: curTimeout, repeats: false, block:{ (time:Timer) in
            self.processTimeout = true
        })
        defer {
            processTimer?.invalidate()
        }
        
        // 5.1.3 - 20
        for authenticator in authenticators {
            if self.processTimeout {break;}
            
            // TODO: support cancel process
            
            // an authenticator becomes available
            if let selection = options.authenticatorSelection {
                if let attachment = selection.authenticatorAttachment {
                    if attachment != authenticator.attachment {continue;}
                }
                
                if let selResidentKey = selection.residentKey  {
                    if selResidentKey == .required
                        && !authenticator.canStoreResidentKey() {continue;}
                } else {
                    if selection.requireResidentKey ?? false
                        && !authenticator.canStoreResidentKey() {continue;}
                }
                
                if selection.userVerification == .required
                    && !authenticator.canPerformUserVerification() {continue;}
            }
            
            var requireResidentKey = options.authenticatorSelection?.requireResidentKey ?? false
            if !requireResidentKey, let rdtKey = options.authenticatorSelection?.residentKey {
                if rdtKey == .required{
                    requireResidentKey = true
                } else if rdtKey == .preferred {
                    requireResidentKey = authenticator.canStoreResidentKey()
                } else if rdtKey == .discouraged {
                    requireResidentKey = false
                }
            }
            
            //Use resident key when no client conf
            if !requireResidentKey {requireResidentKey=authenticator.canStoreResidentKey()}
            
            let userVerification = self.judgeUserVerificationExecution(
                authenticator: authenticator, userVerificationRequest: UserVerificationRequirement(rawValue: (options.authenticatorSelection?.userVerification)!.rawValue) ?? .discouraged)
            
            let userPresence = !userVerification //dqj: A miss of spec?
            
            let enterpriseAttestationPossible = options.attestation == AttestationConveyancePreference.enterprise &&
                                                    LibConfig.enterpriseRPIds.contains(options.rp.id ?? "")
            
            var excludeCredentialDescriptorList: [PublicKeyCredentialDescriptor]
            if Fido2Core.canRegisterMultipleCredByMultipleTransports {
                excludeCredentialDescriptorList = (options.excludeCredentials ?? []).filter {descriptor in
                    if nil != descriptor.transports && descriptor.transports!.contains(authenticator.transport.rawValue) {
                         return false
                     } else {
                         return true
                     }
                }
            } else {
                excludeCredentialDescriptorList = options.excludeCredentials ?? []
            }
            
            let rpEntity = PublicKeyCredentialRpEntity(
                id:   rpId,
                name: options.rp.name,
                icon: options.rp.icon
            )
            guard let attestation=(try await authenticator.authenticatorMakeCredential(
                message:                         message,
                clientDataHash:                  clientDataHash,
                rpEntity:                        rpEntity,
                userEntity:                      options.user,
                requireResidentKey:              requireResidentKey,
                requireUserPresence:             userPresence,
                requireUserVerification:         userVerification,
                credTypesAndPubKeyAlgs:          options.pubKeyCredParams,
                excludeCredentialDescriptorList: excludeCredentialDescriptorList,
                enterpriseAttestationPossible:   enterpriseAttestationPossible,
                extensions:                      Dictionary<String, [UInt8]>() //dqj TODO: support extensions
            )) else {
                continue
            }
            Fido2Logger.debug("authenticatorMakeCredential attObj: \(attestation)")
            
            guard let attestedCred = attestation.authData.attestedCredentialData else {
                Fido2Logger.debug("attested credential data not found")
                throw Fido2Error.new(error: .unknown, message: "attested credential data not found")
            }
            
            let credentialId = attestedCred.credentialId
            Fido2Logger.debug("attestedCred.credentialId: \(credentialId)")
            
            var atts = attestation
            
            // XXX currently not support replacing attestation
            //     on "indirect" conveyance request
            
            var attestationObject: [UInt8]! = nil
            if options.attestation == .none && !attestation.isSelfAttestation() {
                Fido2Logger.debug("attestation conveyance request is 'none', but this is not a self-attestation.")
                atts = attestation.toNone()
                guard let bytes = try atts.toBytes() else {
                    Fido2Logger.debug("failed to build attestation-object")
                    throw Fido2Error.new(error: .unknown, message: "failed to build attestation-object")
                }
                
                attestationObject = bytes
                
                Fido2Logger.debug("replace AAGUID with zero")
                
                let guidPos = 37 // ( rpIdHash(32), flag(1), signCount(4) )
                
                (guidPos..<(guidPos+16)).forEach { attestationObject[$0] = 0x00 }
                
            } else {// direct or enterprise
                guard let bytes = try atts.toBytes() else {
                    Fido2Logger.debug("<CreateOperation> failed to build attestation-object")
                    throw Fido2Error(error: .unknown)
                }
                attestationObject = bytes
                
            }
            
            let response = AuthenticatorAttestationResponse(
                clientDataJSON:    Base64.encodeBase64URL(Array(clientDataJSON.utf8)), //clientDataJSON,
                attestationObject: Base64.encodeBase64URL(attestationObject) //attestationObject
                //dqj TODO: support [[transports]]
            )
            
            // TODO support [[clientExtensionsResults]]
            Fido2Logger.debug("attestedCred.credentialId: \(credentialId)")
            let base64Id = Base64.encodeBase64URL(credentialId)
            let cred = PublicKeyCredential<AuthenticatorAttestationResponse>(
                rawId:    base64Id, //credentialId, //base64Id,// ?cannot send raw data by JSON
                id:       base64Id,
                response: response
            )
            Fido2Logger.debug("createNewCredential cred.rawId: \(cred.rawId)")
            
            return cred
        }
        
        Fido2Logger.debug("newCredential cannot found usable authenticator.")
        
        //Wait timeout and retrun according to WebAuthn spec
        if(Fido2Core.waitCannotFindAuthenticatorTimeout && !self.processTimeout){
            let needWait = curTimeout - (Date().timeIntervalSince1970 - (self.startTime ?? Date().timeIntervalSince1970))
            Fido2Logger.debug("needWait: \(needWait)")
            if 0 < needWait {
                try await Task.sleep(nanoseconds: UInt64(needWait) * 1000 * 1000000 )
            }
        }
        throw Fido2Error(error: .notAllowed)
    }
    
    /// 5.1.3 - 4
    /// If the timeout member of options is present, check if its value lies within a reasonable
    /// range as defined by the client and if not, correct it to the closest value lying within that range.
    /// Set a timer lifetimeTimer to this adjusted value. If the timeout member of options is not present,
    /// then set lifetimeTimer to a client-specific default.
    private func adjustLifetimeTimer(timeout: UInt64, userVerification: UserVerificationRequirement) -> Double {
        if (timeout > 0) {
            let t = Double((timeout) / 1000)
            if (t < self.minTimeout) {
                return self.minTimeout
            }
            if (t > self.maxTimeout) {
                return self.maxTimeout
            }
            return t
        } else {
            var t = self.defaultTimeout
            switch userVerification {
            case .required, .preferred:
                t = 120
            case .discouraged:
                t = 300
            }
            if (t < self.minTimeout) {
                return self.minTimeout
            }
            if (t > self.maxTimeout) {
                return self.maxTimeout
            }
            return t
        }
    }

    /// 5.1.3 - 8 If options.rpId is not present, then set rpId to effectiveDomain.
    private func pickRelyingPartyID(rpId: String?, origin: String) -> String {
        if let _rpId = rpId {
            return _rpId
        } else {
            if let component: NSURLComponents = NSURLComponents(string: origin) {
                return component.host ?? origin
            }else{
                return origin
            }
        }
    }

    // 5.1.3 - 13,14,15 Prepare ClientData, JSON, Hash
    private func generateClientData(
        type:      CollectedClientDataType,
        challenge: String,
        origin: String
        ) -> (CollectedClientData, String, [UInt8]) {

        // TODO TokenBinding
        let clientData = CollectedClientData(
            type:         type,
            challenge:    challenge,
            origin:       origin,
            tokenBinding: nil
        )

        let clientDataJSONData = try! JSONEncoder().encode(clientData)
        let clientDataJSON = String(data: clientDataJSONData, encoding: .utf8)!
        let clientDataHash = SHA256(clientDataJSONData.encodedHexadecimals).calculate32()

        return (clientData, clientDataJSON, clientDataHash)
    }
    
    /// Authentication methods
    /// https://w3c.github.io/webauthn/#sctn-discover-from-external-source
    private func discoverFromExternalSource(options: PublicKeyCredentialRequestOptions, origin: String, message: String,
                                            selectedCredId: [UInt8]?)async throws -> PublicKeyCredential<AuthenticatorAssertionResponse>{
        
        // 5.1.4.1 1-2, 5,6: No need as a lib
        
        // 5.1.4.1 3
        if (options.mediation != nil) && options.mediation == CredentialMediationRequirement.conditional{
            if nil != options.allowCredentials && !options.allowCredentials!.isEmpty {throw Fido2Error(error: .notSupported)}
            curTimeout = 0 //5.1.4.1 3.2 Set a timer lifetimeTimer to a value of infinity.
        }else{
            //5.1.4.1 4
            curTimeout = self.adjustLifetimeTimer(timeout: options.timeout ?? 0, userVerification: options.userVerification ?? .discouraged)
        }
        
        //5.1.4.1 7
        let rpId = self.pickRelyingPartyID(rpId: options.rpId, origin: origin)
        
        // TODO Extension handling
        // 5.1.4.1 - 8,9

        // 5.1.4.1 - 10, 11, 12
        let (_, clientDataJSON, clientDataHash) =
            self.generateClientData(
                type:      .webAuthnGet,
                challenge: options.challenge, //dqj Base64.encodeBase64URL(Array(options.challenge.utf8)),
                origin: origin
        )
        
        // 5.1.4.1 - 14, 15 : dqj TODO: authenticators collection - support issuedRequests, savedCredentialIds
        
        // 5.1.4.1 - 16 : dqj TODO: authenticators collection - support set of authenticators
        let authenticators = [authenticatorPlatform]
        
        // 5.1.4.1 - 18 Start lifetimeTimer.
        if 0 < curTimeout {
            processTimer = Timer.scheduledTimer(withTimeInterval: curTimeout, repeats: false, block:{ (time:Timer) in
                self.processTimeout = true
            })
        }
        defer {
            processTimer?.invalidate()
        }
        
        // 5.1.4.1 - 19
        for authenticator in authenticators {
            if self.processTimeout {break;}
            
            // TODO: support cancel
            
            // TODO: support ConditionalMediation preparation
            
            //an authenticator becomes available
            
            var savedCredentialId: [UInt8]?
            
            var realAllowCredentials = options.allowCredentials ?? [];
            
            //ConditionalMediation silentCredentialDiscovery
            if options.mediation == .conditional && authenticator.canSilentCredentialDiscovery() {
                let pubKeyCreds = try authenticator.silentCredentialDiscovery(rpId: rpId)
                
                //We provide accounts list feature, not Selection UI here.
                if !pubKeyCreds.isEmpty {
                    var pubKeyDesc:PublicKeyCredentialDescriptor
                    if (selectedCredId != nil) {
                        pubKeyDesc = PublicKeyCredentialDescriptor (id: Base64.encodeBase64URL(selectedCredId!), transports: [authenticator.transport.rawValue])
                    }else{
                        if 1 < pubKeyCreds.count {
                            Fido2Logger.info("Discovered more then one credentials, return the first one. Enable AccountsList, list accounts and let user to select credential.")
                        }
                        pubKeyDesc = PublicKeyCredentialDescriptor (id: Base64.encodeBase64URL(pubKeyCreds[0].id), transports: [authenticator.transport.rawValue])
                    }
                    realAllowCredentials = [pubKeyDesc]
                }
            }
                
            //5.1.4.2. Issuing a Credential Request to an Authenticator
                
            if (options.userVerification == .required) && !authenticator.allowUserVerification {
                Fido2Logger.debug("<discoverFromExternalSource> authenticator notsupport userVerification")
                continue
            }
            
            let userVerification = self.judgeUserVerificationExecution(authenticator: authenticator, userVerificationRequest: options.userVerification)
            
            let userPresence = !userVerification
            
            if !realAllowCredentials.isEmpty {
                
                let allowCredentialDescriptorList = realAllowCredentials.filter {
                    // TODO: more check for id.
                    nil == $0.transports || $0.transports!.contains(authenticator.transport.rawValue)
                }
                
                if (allowCredentialDescriptorList.isEmpty) {
                    continue
                }
                
                // need to remember the credential Id
                // because authenticator doesn't return credentialId for single descriptor
                
                if allowCredentialDescriptorList.count == 1 {
                    savedCredentialId = Array(Base64.decodeBase64URLTry(allowCredentialDescriptorList[0].id) ?? Data())
                }
                
                //TODO: select distinctTransports
                /*var distinctTransports = [String]()
                 for aCred in allowCredentialDescriptorList{
                 distinctTransports.append(contentsOf: aCred.transports)
                 }
                 if !distinctTransports.isEmpty {
                 }else{
                 }*/
                
                realAllowCredentials = allowCredentialDescriptorList
            }
            
            guard let assertionResult = try await (authenticator.authenticatorGetAssertion(
                message:                       message,
                rpId:                          rpId,
                clientDataHash:                clientDataHash,
                allowCredentialDescriptorList: realAllowCredentials,
                requireUserPresence:           userPresence,
                requireUserVerification:       userVerification,
                extensions:                    Dictionary<String, [UInt8]>() //dqj TODO: support extensions
            )) else {
                continue
            }
            
            //End of Issuing a Credential Request to an Authenticator
            
            //End of an authenticator becomes available
            
            //authenticator indicates success
            var credentialId: [UInt8]?
            if let savedId = savedCredentialId {
                Fido2Logger.debug("<discoverFromExternalSource> use saved credentialId")
                credentialId = savedId
            } else {
                Fido2Logger.debug("<discoverFromExternalSource> use credentialId from authenticator")
                guard let resultId = assertionResult.credentailId else {
                    Fido2Logger.debug("<discoverFromExternalSource> credentialId not found")
                    throw Fido2Error.new(error: .unknown, message: "<discoverFromExternalSource> credentialId not found")
                }
                credentialId = resultId //String(bytes: resultId, encoding: .utf8)
            }
            
            // TODO support extensionResult
            let cred = PublicKeyCredential<AuthenticatorAssertionResponse>(
                rawId:    Base64.encodeBase64URL(credentialId ?? []), //credentialId!,
                id:       Base64.encodeBase64URL(credentialId ?? []), //Array(credentialId!.utf8)),
                authenticatorAttachment: authenticator.attachment,
                response: AuthenticatorAssertionResponse(
                    clientDataJSON:    Base64.encodeBase64URL(clientDataJSON),
                    authenticatorData: Base64.encodeBase64URL(assertionResult.authenticatorData),
                    signature:         Base64.encodeBase64URL(assertionResult.signature),
                    userHandle:        Base64.encodeBase64URL(assertionResult.userHandle ?? [])
                    //TODO: support [[clientExtensionsResults]]
                )
            )
            
            return cred
        }
        Fido2Logger.debug("discoverFromExternalSource cannot found usable authenticator.")
        
        //Wait timeout and retrun according to WebAuthn spec
        if(Fido2Core.waitCannotFindAuthenticatorTimeout && !self.processTimeout){
            let needWait = curTimeout - (Date().timeIntervalSince1970 - (self.startTime ?? Date().timeIntervalSince1970))
            Fido2Logger.debug("needWait: \(needWait)")
            if 0 < needWait {
                try await Task.sleep(nanoseconds: UInt64(needWait) * 1000 * 1000000 )
            }
        }
        throw Fido2Error(error: .notAllowed)
    }
    
    private func judgeUserVerificationExecution(authenticator: Authenticator, userVerificationRequest: UserVerificationRequirement? = .discouraged) -> Bool {
        switch userVerificationRequest {
        case .required:
            return true
        case .preferred:
            return authenticator.canPerformUserVerification()
        case .discouraged:
            return false
        case .none:
            return authenticator.canPerformUserVerification()
        }
    }
    
    private func httpRequest(url: String, method: String, body: Data,
                             headers: Dictionary<String, String>, cachePolicy: URLRequest.CachePolicy, timeout: Double = 0) async throws -> Data {
        guard let url = URL(string: url) else {
            Fido2Logger.err("<httpRequest> url wrong: \(url)")
            throw Fido2Error.new(error: .unknown, message: "<httpRequest> url wrong: \(url)")
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.cachePolicy = cachePolicy
        for elem in headers {
            let key = elem.key
            let value = elem.value
            Fido2Logger.debug("httpRequest header: \(elem)")
            request.addValue(value, forHTTPHeaderField: key)
        }
        
        request.httpBody = body
        
        if 0 < timeout {request.timeoutInterval = timeout}
        
        let reqsession = URLSession(configuration: .default, delegate: myUrlSessionDelegate(), delegateQueue: nil)
        
        let (data, _) = try await reqsession.data(for: request)

        return data
    }
}

internal class myUrlSessionDelegate : NSObject, URLSessionDelegate{
    /**
        For self sign cert, add keys below into info.plist first:
         <dict>
             <key>NSAppTransportSecurity</key>
             <dict>
                 <key>NSExceptionDomains</key>
                 <dict>
                     <key>dqj-macpro.com</key>
                     <dict>
                         <key>NSIncludesSubdomains</key>
                         <true/>
                         <key>NSTemporaryExceptionAllowsInsecureHTTPLoads</key>
                         <true/>
                     </dict>
                 </dict>
             </dict>
         </dict>
    */
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge) async -> (URLSession.AuthChallengeDisposition, URLCredential?){
        if challenge.protectionSpace.host.hasSuffix("dqj-macpro.com") {//Change to your local test domain if need.
            return (.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
        } else {
            return (.performDefaultHandling, nil)
        }
    }

}

public struct Account : Codable{
    public var rpid: String
    public var username: String
    public var displayname: String
    public var credIdBase64: String
    
    public func toJSON() -> Optional<String>{
        return JSONHelper<Account>.encode(self)
    }
    
    public static func fromJSON(json: String) -> Optional<Account> {
        guard let rtn = JSONHelper<Account>.decode(json) else {
            return nil
        }
        return rtn
    }
}

public struct Accounts : Codable{
    public var accounts: [Account]
    
    public func toJSON() -> Optional<String>{
        return JSONHelper<Accounts>.encode(self)
    }
    
    public static func fromJSON(json: String) -> Optional<Accounts> {
        guard let rtn = JSONHelper<Accounts>.decode(json) else {
            return nil
        }
        return rtn
    }
}

//Passkeys

class AuthorizationManager: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding{
    var resultReg:              ASAuthorizationPlatformPublicKeyCredentialRegistration?
    var resultAuth:             ASAuthorizationPlatformPublicKeyCredentialAssertion?
    
    var errorCode: ASAuthorizationError.Code?
    
    private var activeRegContinuation: CheckedContinuation<ASAuthorizationPlatformPublicKeyCredentialRegistration, Error>?
    private var activeAuthContinuation: CheckedContinuation<ASAuthorizationPlatformPublicKeyCredentialAssertion, Error>?

    func startAuthentication(rpDomain: String, challenge:Data) async throws -> ASAuthorizationPlatformPublicKeyCredentialAssertion {
        return try await withCheckedThrowingContinuation { continuation in
            activeAuthContinuation = continuation
            
            let publicKeyCredentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpDomain)
            
            let authRequest = publicKeyCredentialProvider.createCredentialAssertionRequest(challenge: challenge)
            
            let authController = ASAuthorizationController(authorizationRequests: [ authRequest ] )
            authController.delegate = self
            authController.presentationContextProvider = self
            authController.performRequests()
        }
    }
    
    func startRegistration(rpDomain: String, pubkeyCredOpts: PublicKeyCredentialCreationOptions, allowMultipleRegistration: Bool = false ) async throws -> ASAuthorizationPlatformPublicKeyCredentialRegistration {
        if(!allowMultipleRegistration && !(pubkeyCredOpts.excludeCredentials?.isEmpty ?? true)){
            throw Fido2Error(error: .invalidState)
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            activeRegContinuation = continuation
            
            let publicKeyCredentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpDomain)
            
            let registrationRequest = publicKeyCredentialProvider.createCredentialRegistrationRequest(
                challenge: pubkeyCredOpts.challenge.data(using: .utf8)!, name: pubkeyCredOpts.user.name, userID: pubkeyCredOpts.user.id.data(using: .utf8)!)
            
            /* For security keys, may support in the future.
            let publicKeyCredentialProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: rpDomain)
            
            let registrationRequest = publicKeyCredentialProvider.createCredentialRegistrationRequest(
                challenge: pubkeyCredOpts.challenge.data(using: .utf8)!, displayName: pubkeyCredOpts.user.displayName,
                name: pubkeyCredOpts.user.name,
                userID: pubkeyCredOpts.user.id.data(using: .utf8)!);
            registrationRequest.attestationPreference = ASAuthorizationPublicKeyCredentialAttestationKind(rawValue:pubkeyCredOpts.attestation.rawValue)
            if(nil != pubkeyCredOpts.authenticatorSelection){
                registrationRequest.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreference(rawValue: pubkeyCredOpts.authenticatorSelection!.userVerification.rawValue)
                if(nil != pubkeyCredOpts.authenticatorSelection!.residentKey){
                    registrationRequest.residentKeyPreference = ASAuthorizationPublicKeyCredentialResidentKeyPreference(rawValue: pubkeyCredOpts.authenticatorSelection!.residentKey!.rawValue)
                }
                
            }
            pubkeyCredOpts.pubKeyCredParams.forEach{ para in
                let alg = ASCOSEAlgorithmIdentifier(rawValue: para.getCOSEAlgorithmIdentifier().rawValue)
                let npara = ASAuthorizationPublicKeyCredentialParameters(algorithm: alg)
                registrationRequest.credentialParameters.append(npara)
            }
            
            if(nil != pubkeyCredOpts.excludeCredentials){
                pubkeyCredOpts.excludeCredentials!.forEach { cred in
                    var ntransports:[ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport] = []
                    if(nil != cred.transports){
                        cred.transports?.forEach{ tp in
                            ntransports.append(ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport(rawValue: tp))
                        }
                    }
                    let ncred = ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                        credentialID: cred.id.data(using: .utf8)!,
                        transports: ntransports)
                    
                    registrationRequest.excludedCredentials.append(ncred)
                }
            }
            */
            
            let authController = ASAuthorizationController(authorizationRequests: [ registrationRequest ] )
            authController.delegate = self
            authController.presentationContextProvider = self
            authController.performRequests()
        }
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        switch authorization.credential {
        case let credentialRegistration as ASAuthorizationPlatformPublicKeyCredentialRegistration:
            Fido2Logger.debug("New passkey registered: \(credentialRegistration)")
            resultReg = credentialRegistration
            activeRegContinuation?.resume(returning: credentialRegistration)
            activeRegContinuation = nil
        case let credentialAssertion as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            Fido2Logger.debug("Passkey Auth: \(credentialAssertion)")
            resultAuth = credentialAssertion
            activeAuthContinuation?.resume(returning: credentialAssertion)
            activeAuthContinuation = nil
        default:
            fatalError("Unknown authorization type.")
        }
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        Fido2Logger.err("AuthorizationManager fail: \((error as NSError).userInfo)")
        guard let authorizationError = error as? ASAuthorizationError else {
            errorCode = .unknown
            Fido2Logger.err("Unexpected authorization error: \(error.localizedDescription)")
            return
        }
        errorCode = authorizationError.code
        if(nil != activeAuthContinuation){
            activeAuthContinuation?.resume(throwing: error)
            activeAuthContinuation = nil
        }else{
            activeRegContinuation?.resume(throwing: error)
            activeRegContinuation = nil
        }
    }
    
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        let scenes = UIApplication.shared.connectedScenes
        let windowScene = scenes.first as? UIWindowScene
        let window = (windowScene?.windows.first)!
        return window
    }
}
