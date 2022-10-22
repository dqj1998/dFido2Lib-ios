//
//  Authenticator.swift
//  dFido2LibCore
//
//  From Lyo Kato's Authenticator folder of WebAuthnKit
//  Created by Du Qingjie on 2022/08/21.
//
//  6 - WebAuthn Authenticator Model (https://w3c.github.io/webauthn/#sctn-authenticator-model)

import Foundation
import LocalAuthentication
import Security
import CryptoKit
import WebKit //.CBORWriter

// MARK: Data

public struct AuthenticatorDataFlags {
    public let UPMask: UInt8 = 0b00000001
    public let UVMask: UInt8 = 0b00000100
    public let BEMask: UInt8 = 0b00001000
    public let BSMask: UInt8 = 0b00010000
    public let ATMask: UInt8 = 0b01000000
    public let EDMask: UInt8 = 0b10000000

    public var userPresent: Bool = false
    public var userVerified: Bool = false
    public var backupEligibility : Bool = false
    public var backupState : Bool = false
    public var hasAttestedCredentialData: Bool = false
    public var hasExtension: Bool = false

    init(
        userPresent: Bool,
        userVerified: Bool,
        backupEligibility: Bool,
        backupState: Bool,
        hasAttestedCredentialData: Bool,
        hasExtension: Bool
    ) {
        self.userPresent               = userPresent
        self.userVerified              = userVerified
        self.backupEligibility         = backupEligibility
        self.backupState               = backupState
        self.hasAttestedCredentialData = hasAttestedCredentialData
        self.hasExtension              = hasExtension
    }

    init(flags: UInt8) {
        userPresent               = ((flags & UPMask) == UPMask)
        userVerified              = ((flags & UVMask) == UVMask)
        backupEligibility         = ((flags & BEMask) == BEMask)
        backupState               = ((flags & BSMask) == BSMask)
        hasAttestedCredentialData = ((flags & ATMask) == ATMask)
        hasExtension              = ((flags & EDMask) == EDMask)

        Fido2Logger.debug("<AuthenticatorDataFlags> UP:\(userPresent)")
        Fido2Logger.debug("<AuthenticatorDataFlags> UV:\(userVerified)")
        Fido2Logger.debug("<AuthenticatorDataFlags> BE:\(backupEligibility)")
        Fido2Logger.debug("<AuthenticatorDataFlags> BS:\(backupState)")
        Fido2Logger.debug("<AuthenticatorDataFlags> AT:\(hasAttestedCredentialData)")
        Fido2Logger.debug("<AuthenticatorDataFlags> ED:\(hasExtension)")
    }

    public func toByte() -> UInt8 {
        var flags: UInt8 = 0b00000000
        if self.userPresent {
            Fido2Logger.debug("<AuthenticatorDataFlags> UP:on")
            flags = flags | UPMask
        }
        if self.userVerified {
            Fido2Logger.debug("<AuthenticatorDataFlags> UV:on")
            flags = flags | UVMask
        }
        if self.backupEligibility {
            Fido2Logger.debug("<AuthenticatorDataFlags> BE:on")
            flags = flags | BEMask
        }
        if self.backupState {
            Fido2Logger.debug("<AuthenticatorDataFlags> BS:on")
            flags = flags | BSMask
        }
        if self.hasAttestedCredentialData {
            Fido2Logger.debug("<AuthenticatorDataFlags> AT:on")
            flags = flags | ATMask
        }
        if self.hasExtension {
            Fido2Logger.debug("<AuthenticatorDataFlags> ED on")
            flags = flags | EDMask
        }
        return flags
    }
}

public struct AttestedCredentialData {

    let aaguid:              [UInt8] // 16byte
    let credentialId:        [UInt8]
    let credentialPublicKey: SecKey

    public func toBytes() throws -> [UInt8] {
        if self.aaguid.count != 16 {
           fatalError("<AttestedCredentialData> invalid aaguid length")
        }
        var result = self.aaguid
        let credentialIdLength = credentialId.count
        result.append(UInt8((credentialIdLength & 0xff00) >> 8))
        result.append(UInt8((credentialIdLength & 0x00ff)))
        result.append(contentsOf: credentialId)
        
        guard let attrPub = SecKeyCopyAttributes(credentialPublicKey) as? [CFString: Any],
            let keyType = attrPub[kSecAttrKeyType] as? String else {
            Fido2Logger.err("Fail to get kSecAttrKeyType")
            throw Fido2Error.new(error: .badData, message: "Fail to get kSecAttrKeyType")
        }
        
        let keySize = attrPub[kSecAttrKeySizeInBits] as! Int
        let pubData  = attrPub[kSecValueData] as! Data
        var modulus  = pubData.subdata(in: 8..<(pubData.count - 5))
        let exponent = pubData.subdata(in: (pubData.count - 3)..<pubData.count)
        if modulus.count > keySize / 8 { // --> 257 bytes
            modulus.removeFirst(1)
        }
        
        let dic = SimpleOrderedDictionary<Int>()
        if keyType == (kSecAttrKeyTypeRSA as String){
            dic.addInt(COSEKeyFieldType.kty, Int64(COSEKeyType.rsa))
            switch(attrPub[kSecAttrKeySizeInBits] as! Int){
            case 256*8:
                dic.addInt(COSEKeyFieldType.alg, Int64(COSEAlgorithmIdentifier.rs256.rawValue))
            case 384*8:
                dic.addInt(COSEKeyFieldType.alg, Int64(COSEAlgorithmIdentifier.rs384.rawValue))
            case 512*8:
                dic.addInt(COSEKeyFieldType.alg, Int64(COSEAlgorithmIdentifier.rs512.rawValue))
            default:
                Fido2Logger.err("Unsupported kSecAttrKeySizeInBits")
                throw Fido2Error.new(error: .notSupported, message: "Unsupported kSecAttrKeySizeInBits")
            }
            
            dic.addBytes(COSEKeyFieldType.n, modulus.encodedHexadecimals)
            dic.addBytes(COSEKeyFieldType.e, exponent.encodedHexadecimals)
        } else {
            Fido2Logger.err("Only support RSA now")
            throw Fido2Error.new(error: .notSupported, message: "Only support RSA now")
        }
        
        let pubkBtyes = CBORWriter().putIntKeyMap(dic).getResult()
        
        result.append(contentsOf: pubkBtyes)
        
        return result
    }
    
    public static func fromBytes(_ bytes: [UInt8]) throws -> (data: AttestedCredentialData, size: Int) {
        var pos = 0
        let aaguid = Array(bytes[pos..<(pos+16)])

        pos = pos + 16

        let len = Int((UInt16(bytes[pos]) << 8) | UInt16(bytes[pos+1]))

        pos = pos + 2

        let credentialId = Array(bytes[pos..<(pos+len)])

        pos = pos + len

        let keylen = Int((UInt16(bytes[pos]) << 8) | UInt16(bytes[pos+1]))
        
        pos = pos + 2
        
        let keydata = Array(bytes[pos..<(pos+keylen)])
        let sizeInBits = keydata.count * 8
        let keyDict: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA, //Only support RSA
            kSecAttrKeySizeInBits: NSNumber(value: sizeInBits)
        ]
        var error: Unmanaged<CFError>?
        let pubkey = SecKeyCreateWithData(Data(keydata) as CFData, keyDict as CFDictionary, &error)!
        if (error != nil) {
            Fido2Logger.err("<AttestedCredentialData> SecKeyCreateWithData failed")
            throw Fido2Error.new(error: .badData, details: error!.takeRetainedValue())
        }
        
        return (data: AttestedCredentialData(
            aaguid:              aaguid,
            credentialId:        credentialId,
            credentialPublicKey: pubkey
        ), size: pos+keylen)
    }
}

public struct AuthenticatorData {
    
    let rpIdHash:               [UInt8]
    let userPresent:            Bool
    let userVerified:           Bool
    let backupEligibility:      Bool
    let backupState:            Bool
    let signCount:              UInt32
    let attestedCredentialData: AttestedCredentialData?
    let extensions:             SimpleOrderedDictionary<String>;

    public static func fromBytes(_ bytes: [UInt8]) throws -> Optional<AuthenticatorData> {
        Fido2Logger.debug("<AuthenticatorData> fromBytes")
        if bytes.count < 37 {
            Fido2Logger.debug("<AuthenticatorData> byte-size is not enough")
            throw Fido2Error.new(error: .badData, message: "<AuthenticatorData> byte-size is not enough")
        }
        let rpIdHash: [UInt8] = Array(bytes[0..<32])

        let flags = AuthenticatorDataFlags(flags: bytes[32])

        let signCount = UInt32((UInt32(bytes[33]) << 24) | (UInt32(bytes[34]) << 16) | (UInt32(bytes[35]) << 8) | UInt32(bytes[36]))


        Fido2Logger.debug("<AuthenticatorData> sing-count:\(signCount)")

        var pos = 37

        var attestedCredentialData: AttestedCredentialData? = nil

        if flags.hasAttestedCredentialData {

            if bytes.count < (pos + 16 + 2) {
                Fido2Logger.debug("<AuthenticatorData> byte-size is not enough")
                throw Fido2Error.new(error: .badData, message: "<AuthenticatorData> byte-size is not enough")
            }

            let rest = Array(bytes[pos..<bytes.count])
            var readSize = 0
            
            do{
                (attestedCredentialData, readSize) = try AttestedCredentialData.fromBytes(rest)
            }catch{
                Fido2Logger.debug("<AuthenticatorData> failed to read CBOR for AttestedCredentialData")
                throw Fido2Error.new(error: .badData, message: "<AuthenticatorData> failed to read CBOR for AttestedCredentialData")
            }
            
            pos = pos + readSize
        }

        var extensions = SimpleOrderedDictionary<String>()

        if flags.hasExtension {

            let rest = Array(bytes[pos..<bytes.count])

            guard let params = CBORReader(bytes: rest).readStringKeyMap() else {
                Fido2Logger.debug("<AuthenticatorData> failed to read CBOR for extensions")
                throw Fido2Error.new(error: .badData, message: "<AuthenticatorData> failed to read CBOR for extensions")
            }

            extensions = SimpleOrderedDictionary<String>.fromDictionary(params)
        }

        return AuthenticatorData(
            rpIdHash:               rpIdHash,
            userPresent:            flags.userPresent,
            userVerified:           flags.userVerified,
            backupEligibility:      flags.backupEligibility,
            backupState:            flags.backupState,
            signCount:              signCount,
            attestedCredentialData: attestedCredentialData,
            extensions:             extensions
        )

    }

    public func toBytes() throws -> [UInt8] {
        Fido2Logger.debug("<AuthenticatorData> toBytes")

        if self.rpIdHash.count != 32 {
            fatalError("<AuthenticatorData> rpIdHash should be 32 bytes")
        }

        var result = self.rpIdHash

        let flags: UInt8 = AuthenticatorDataFlags(
            userPresent:               self.userPresent,
            userVerified:              self.userVerified,
            backupEligibility:         self.backupEligibility,
            backupState:               self.backupState,
            hasAttestedCredentialData: (self.attestedCredentialData != nil),
            hasExtension:              !self.extensions.isEmpty
        ).toByte()

        result.append(flags)

        result.append(UInt8((signCount & 0xff000000) >> 24))
        result.append(UInt8((signCount & 0x00ff0000) >> 16))
        result.append(UInt8((signCount & 0x0000ff00) >>  8))
        result.append(UInt8((signCount & 0x000000ff)))

        if let attestedData = self.attestedCredentialData {
            result.append(contentsOf: try attestedData.toBytes())
        }

        if !self.extensions.isEmpty {
            let builder = CBORWriter()
            _ = builder.putStringKeyMap(self.extensions)
            result.append(contentsOf: builder.getResult())
        }

        return result
    }
}

public struct PublicKeyCredentialSource {
    
    var type:       PublicKeyCredentialType = .publicKey
    //var signCount:  UInt32 = 0
    var id:         [UInt8] // credential id
    var privateKey: SecKey
    var rpId:       String
    var userHandle: [UInt8]
    //var alg:        Int = COSEAlgorithmIdentifier.rs256.rawValue
    var otherUI:    String
    
    init(
        id:         [UInt8],
        privateKey: SecKey,
        rpId:       String,
        userHandle: [UInt8],
        //signCount:  UInt32,
        //alg:        Int,
        otherUI:    String=""
        ) {
        
        self.id         = id
        self.privateKey = privateKey
        self.rpId       = rpId
        self.userHandle = userHandle
        //self.signCount  = signCount
        //self.alg        = alg
        self.otherUI    = otherUI
    }
    
    public func toCBOR() throws -> Optional<[UInt8]> {
        Fido2Logger.debug("<PublicKeyCredentialSource> toCBOR")
        
        let builder = CBORWriter()
        
        let dict = SimpleOrderedDictionary<String>()
        
        dict.addBytes("id",self.id)
        dict.addString("rpId", self.rpId)
        dict.addBytes("userHandle", self.userHandle)
        var error: Unmanaged<CFError>?
        guard let rawdata = SecKeyCopyExternalRepresentation(privateKey, &error) as? Data else {
            Fido2Logger.err("SecKeyCopyExternalRepresentation failed")
            throw Fido2Error.new(error: .unknown, message: "SecKeyCopyExternalRepresentation failed")
        }
        dict.addBytes("privateKey", rawdata.encodedHexadecimals)
        //dict.addInt("alg", Int64(self.alg))
        //dict.addInt("signCount", Int64(self.signCount))
        dict.addString("otherUI", self.otherUI)
        return builder.putStringKeyMap(dict).getResult()
    }
    
    public static func fromCBOR(_ bytes: [UInt8]) throws -> Optional<PublicKeyCredentialSource> {
        Fido2Logger.debug("<PublicKeyCredentialSource> fromCBOR")
        
        var id:         [UInt8]
        var privateKey: SecKey
        var rpId:       String = ""
        var userHandle: [UInt8]
        //var algId:      Int = 0
        var otherUI:    String = ""
        //var signCount:  UInt32 = 0
        
        guard let dict = CBORReader(bytes: bytes).readStringKeyMap()  else {
            return nil
        }
        
        if let foundId = dict["id"] as? [UInt8] {
            id = foundId
        } else {
            Fido2Logger.debug("<PublicKeyCredentialSource> id not found")
            throw Fido2Error.new(error: .badData, message: "<PublicKeyCredentialSource> id not found")
        }
        
        if let foundPk = dict["privateKey"] as? [UInt8] {
            let sizeInBits = foundPk.count * 8
            let keyDict: [CFString: Any] = [
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrKeyType: kSecAttrKeyTypeRSA, //Only support RSA
                kSecAttrKeySizeInBits: NSNumber(value: sizeInBits)
            ]
            var error: Unmanaged<CFError>?
            privateKey = SecKeyCreateWithData(Data(foundPk) as CFData, keyDict as CFDictionary, &error)!
            if (error != nil) {
                Fido2Logger.debug("<PublicKeyCredentialSource> SecKeyCreateWithData failed")
                throw Fido2Error.new(error: .badData, message: "<PublicKeyCredentialSource> SecKeyCreateWithData failed")
            }
        } else {
            Fido2Logger.debug("<PublicKeyCredentialSource> privateKey not found")
            throw Fido2Error.new(error: .badData, message: "<PublicKeyCredentialSource> privateKey not found")
        }
        
        /*if let foundSignCount = dict["signCount"] as? Int64 {
            signCount = UInt32(foundSignCount)
        } else {
            Fido2Logger.debug("<PublicKeyCredentialSource> signCount not found")
         throw Fido2Error.new(error: .badData, message: "<PublicKeyCredentialSource> signCount not found")
        }*/
        
        if let foundOtherUI = dict["otherUI"] as? String {
            otherUI = foundOtherUI
        } else {
            Fido2Logger.debug("<PublicKeyCredentialSource> otherUI not found")
            throw Fido2Error.new(error: .badData, message: "<PublicKeyCredentialSource> otherUI not found")
        }
        
        if let foundRpId = dict["rpId"] as? String {
            rpId = foundRpId
        } else {
            Fido2Logger.debug("<PublicKeyCredentialSource> rpId not found")
            throw Fido2Error.new(error: .badData, message: "<PublicKeyCredentialSource> rpId not found")
        }
        
        if let handle = dict["userHandle"] as? [UInt8] {
            userHandle = handle
        } else {
            Fido2Logger.debug("<PublicKeyCredentialSource> userHandle not found")
            throw Fido2Error.new(error: .badData, message: "<PublicKeyCredentialSource> userHandle not found")
        }
        
        /*if let alg = dict["alg"] as? Int64 {
            algId = Int(alg)
        } else {
            Fido2Logger.debug("<PublicKeyCredentialSource> alg not found")
            throw Fido2Error.new(error: .badData, message: "<PublicKeyCredentialSource> alg not found")
        }*/
        
        let src = PublicKeyCredentialSource(
            id:         id,
            privateKey: privateKey,
            rpId:       rpId,
            userHandle: userHandle,
            //signCount:  signCount,
            //alg:        algId,
            otherUI:    otherUI
        )
        return src
    }
}

public class AttestationObject {

    let fmt: String
    let authData: AuthenticatorData
    let attStmt: SimpleOrderedDictionary<String>

    init(fmt:      String,
         authData: AuthenticatorData,
         attStmt:  SimpleOrderedDictionary<String>) {

        self.fmt      = fmt
        self.authData = authData
        self.attStmt  = attStmt
    }

    public func toNone() -> AttestationObject {
        // TODO copy authData with aaguid=0
        return AttestationObject(
            fmt: "none",
            authData: self.authData,
            attStmt: SimpleOrderedDictionary<String>()
        )
    }

    public func isSelfAttestation() -> Bool {
        if self.fmt != "packed" {
            return false
        }
        if let _ = self.attStmt.get("x5c") {
            return false
        }
        if let _ = self.attStmt.get("ecdaaKeyId") {
            return false
        }
        guard let attestedCred = self.authData.attestedCredentialData else {
            return false
        }
        if attestedCred.aaguid.contains(where: { $0 != 0x00 }) {
            return false
        }
        return true
    }

    public func toBytes() throws -> Optional<[UInt8]> {

        let dict = SimpleOrderedDictionary<String>()
        dict.addBytes("authData", try self.authData.toBytes())
        dict.addString("fmt", "packed")
        dict.addStringKeyMap("attStmt", self.attStmt)

        return CBORWriter()
            .putStringKeyMap(dict)
            .getResult()
    }

}

public struct AuthenticatorAssertionResult {
    var credentailId: [UInt8]?
    var userHandle: [UInt8]?
    var signature: [UInt8]
    var authenticatorData: [UInt8]
    init(authenticatorData: [UInt8], signature: [UInt8]) {
        self.authenticatorData = authenticatorData
        self.signature = signature
    }
}

// MARK: APIs

private let pnmSelectedAlg: String = "selectedAlg"

public protocol Authenticator {
    
    var attachment: AuthenticatorAttachment { get }
    var transport: AuthenticatorTransport { get }
    
    var counterStep: UInt32 { set get }
    var allowUserVerification: Bool { get }
    
    func authenticatorMakeCredential(
        message:                         String,
        clientDataHash:                  [UInt8],
        rpEntity:                        PublicKeyCredentialRpEntity,
        userEntity:                      PublicKeyCredentialUserEntity,
        requireResidentKey:              Bool,
        requireUserPresence:             Bool,
        requireUserVerification:         Bool,
        credTypesAndPubKeyAlgs:          [PublicKeyCredentialParameters],
        excludeCredentialDescriptorList: [PublicKeyCredentialDescriptor],
        enterpriseAttestationPossible:   Bool,
        extensions:                      Dictionary<String, [UInt8]>
    ) async throws -> Optional<AttestationObject>
    
    func authenticatorGetAssertion (
        message:                       String,
        rpId:                          String,
        clientDataHash:                [UInt8],
        allowCredentialDescriptorList: [PublicKeyCredentialDescriptor],
        requireUserPresence:           Bool,
        requireUserVerification:       Bool,
        extensions:                    Dictionary<String, [UInt8]>
    ) async throws -> Optional<AuthenticatorAssertionResult>
    
    func lookupCredentialSource(rpId: String, credentialId: [UInt8]) throws -> Optional<PublicKeyCredentialSource>
    
    func silentCredentialDiscovery(rpId: String) throws -> [PublicKeyCredentialSource]
        
    func canStoreResidentKey() -> Bool
    func canPerformUserVerification () -> Bool
    func canSilentCredentialDiscovery() -> Bool
    
    static func reset() -> Bool
}

//MARK: Platform Authenticator

public class PlatformAuthenticator: Authenticator{
    public static var servicePrefix: String = "dFido2Lib_seckey_"
    
    public static var enableResidentStorage: Bool = true
    public static var enableSilentCredentialDiscovery: Bool = true
    
    public let attachment: AuthenticatorAttachment = .platform
    public let transport: AuthenticatorTransport = .internal_
    
    public var counterStep: UInt32
    public var allowUserVerification: Bool
      
    private static let encryptDataAlg:     SecKeyAlgorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA512AESGCM
    private static let credentialStore:    KeychainCredentialStore = KeychainCredentialStore()
    
    private static let nonResidentSecKeyRP = "nonresident-RP"
    private static let nonResidentSecKeyId = "nonresident-ID"
    private static let nonResidentSecKeyAlgPara = [
        kSecAttrKeyClass        : kSecAttrKeyClassPrivate,
        kSecAttrKeyType         : kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits   : 512*8
    ] as CFDictionary
    
    public init(
        counterStep:           UInt32 = 1,
        allowUserVerification: Bool = true
    ) {
        self.counterStep           = counterStep
        self.allowUserVerification = allowUserVerification
        
        //init non-resident keys
        do{
            if try PlatformAuthenticator.credentialStore.retrieveKey(keyChainId: PlatformAuthenticator.nonResidentSecKeyRP,
                                                    handle: PlatformAuthenticator.nonResidentSecKeyId) == nil {
                
                var error: Unmanaged<CFError>?
                let privateKey = SecKeyCreateRandomKey(PlatformAuthenticator.nonResidentSecKeyAlgPara, &error)
                if nil != error {
                    throw Fido2Error.new(error: .unknown, message: "Init PlatformAuthenticator fail \(String(describing: error))")
                }
                
                guard let rawdata = SecKeyCopyExternalRepresentation(privateKey!, &error) as? Data else {
                    throw Fido2Error.new(error: .unknown, message: "Init PlatformAuthenticator fail \(String(describing: error))")
                }
                try PlatformAuthenticator.credentialStore.saveKey(keyChainId: PlatformAuthenticator.nonResidentSecKeyRP, handle:
                                                PlatformAuthenticator.nonResidentSecKeyId, key: rawdata)
            }
        } catch {
            Fido2Logger.err("Init PlatformAuthenticator fail \(error)")
        }
    }
    
    public func canStoreResidentKey() -> Bool {
        return PlatformAuthenticator.enableResidentStorage;
    }
    
    public func canPerformUserVerification() -> Bool {
        return true;
    }
    
    public func canSilentCredentialDiscovery() -> Bool {
        return PlatformAuthenticator.enableSilentCredentialDiscovery;
    }
    
    public static func reset() -> Bool {
        do{
            try self.credentialStore.removeAll()
            return true
        } catch {
            Fido2Logger.debug("reset fail")
            return false
        }
    }
    
    public static func clearKeys(rpId:String="") -> Bool {
        do{
            try self.credentialStore.removeAll(
                but: [PlatformAuthenticator.servicePrefix + PlatformAuthenticator.nonResidentSecKeyRP,
                      PlatformAuthenticator.servicePrefix + PlatformAuthenticator.nonResidentSecKeyId], rpId: rpId)
            return true
        } catch {
            Fido2Logger.debug("reset fail")
            return false
        }
    }
    
    public func authenticatorMakeCredential(message: String, clientDataHash: [UInt8], rpEntity: PublicKeyCredentialRpEntity, userEntity: PublicKeyCredentialUserEntity, requireResidentKey: Bool, requireUserPresence: Bool, requireUserVerification: Bool, credTypesAndPubKeyAlgs: [PublicKeyCredentialParameters], excludeCredentialDescriptorList: [PublicKeyCredentialDescriptor], enterpriseAttestationPossible: Bool, extensions: Dictionary<String, [UInt8]>) async throws -> Optional<AttestationObject> {
        
        let requestedAlgs = credTypesAndPubKeyAlgs.map { $0.getCOSEAlgorithmIdentifier() }
        
        var keyPara:CFDictionary
        do{
            keyPara = try getKeyGeneratePara(requestedAlgorithms:requestedAlgs)
            Fido2Logger.debug("<getKeyGeneratePara> keyPara: \(keyPara)")
        } catch {
            Fido2Logger.debug("<getKeyGeneratePara> fail")
            throw Fido2Error.new(error: .notSupported, message: "<getKeyGeneratePara> fail")
        }
        
        var hasSourceToBeExcluded = try excludeCredentialDescriptorList.contains {
            try PlatformAuthenticator.credentialStore.lookupCredentialSource(
                rpId:         rpEntity.id!,
                credentialId: Array(Base64.decodeBase64URLTry($0.id) ?? Data())
            ) != nil
        }
        
        if !hasSourceToBeExcluded && !excludeCredentialDescriptorList.isEmpty {//Check non-resident
            if let pkey = try PlatformAuthenticator.credentialStore.retrieveKey(keyChainId: PlatformAuthenticator.nonResidentSecKeyRP, handle: PlatformAuthenticator.nonResidentSecKeyId) {
                var error: Unmanaged<CFError>?
                for cred in excludeCredentialDescriptorList{
                    do{
                        let credId = cred.id
                        Fido2Logger.debug("excludeCredentialDescriptorList credId: \(credId)")
                        let csCBOR = try decryptData(data: [UInt8](Base64.decodeBase64URL(credId) ?? Data()),
                                                         privateKey: SecKeyCreateWithData(pkey as CFData, PlatformAuthenticator.nonResidentSecKeyAlgPara, &error)!,
                                                         encryptDataAlg:PlatformAuthenticator.encryptDataAlg)
                        let credSrc = try PublicKeyCredentialSource.fromCBOR(csCBOR)
                        if nil != credSrc && credSrc?.rpId == rpEntity.id {hasSourceToBeExcluded = true; break;}
                    }catch{
                        //do nothing try next
                        Fido2Logger.debug("decryptData fail, try next. \(error)")
                    }
                }
            }
        }
        
        if hasSourceToBeExcluded {
            throw Fido2Error(error: .invalidState)
        }
        
        if requireResidentKey && !self.canStoreResidentKey() {
            throw Fido2Error(error: .constraint)
        }
        
        if requireUserVerification && !self.allowUserVerification {
            Fido2Logger.debug("<authenticatorMakeCredential> insufficient capability (user verification)")
            throw Fido2Error.new(error: .constraint, message: "<authenticatorMakeCredential> insufficient capability (user verification)")
        }
        
        //dqj TODO: UI interaction
        try await self.requestUserConsent(message: message)
        
        //let keyLabel = rpEntity.id! + userEntity.id
        
        var publicKey:SecKey
        var error: Unmanaged<CFError>?
        let privateKey = SecKeyCreateRandomKey(keyPara, &error)
        if nil != error {
            Fido2Logger.err(error.debugDescription)
            throw Fido2Error(error: .unknown)
        }
        
        //dqj for debug
        /*guard let secKeyData = SecKeyCopyExternalRepresentation(privateKey!, &error) as? Data else {
            //Fido2Logger.err("SecKeyCopyExternalRepresentation failed")
            return nil
        }
        let base64EncodedPKCS1 = secKeyData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        Fido2Logger.debug("rawdataPrvKey: \(base64EncodedPKCS1)")*/
        //end of for debug
        
        publicKey = SecKeyCopyPublicKey(privateKey!)!
        //Fido2Logger.debug("SecKeyCopyPublicKey: \(publicKey)")
        
        var credentialId: [UInt8] = []
        
        var credSource = PublicKeyCredentialSource(
            id: credentialId, privateKey: privateKey!,
            rpId:       rpEntity.id!,
            userHandle: Array(Base64.decodeBase64URLTry(userEntity.id) ?? Data())
        )
        
        if requireResidentKey {
            credentialId = UUIDHelper.toBytes(UUID())
            credSource.id = credentialId
            Fido2Logger.debug("authenticatorMakeCredential-credSource(resident-key): \(credSource)")
            
            try PlatformAuthenticator.credentialStore.deleteAllCredentialSources(
                rpId:       credSource.rpId,
                userHandle: credSource.userHandle
            )

            // No keys in KeyChain becaseu we don't use attributes kSecAttrIsPermanent
            
            try PlatformAuthenticator.credentialStore.saveCredentialSource(credSource)
            
        } else {
            if let pkey = try PlatformAuthenticator.credentialStore.retrieveKey(keyChainId: PlatformAuthenticator.nonResidentSecKeyRP,
                                                               handle: PlatformAuthenticator.nonResidentSecKeyId){
                Fido2Logger.debug("retrieveKey: \(String(describing: pkey))")
                
                let csCBOR = try credSource.toCBOR()
                do{
                    var error: Unmanaged<CFError>?
                    if let secKey = SecKeyCreateWithData(pkey as CFData, PlatformAuthenticator.nonResidentSecKeyAlgPara, &error) {
                        if let pubKey = SecKeyCopyPublicKey(secKey) {
                            credentialId = try encryptData(data: csCBOR!,
                                                           publicKey: pubKey,
                                                           encryptDataAlg: PlatformAuthenticator.encryptDataAlg)
                            
                            //for debug
                            //let decrp = try decryptData(data: credentialId, privateKey: secKey, encryptDataAlg: PlatformAuthenticator.encryptDataAlg)
                            //Fido2Logger.debug("debug decryptData: \(decrp)")
                            
                        } else {
                            Fido2Logger.err("SecKeyCopyPublicKey fail. \(String(describing: error))")
                            throw Fido2Error.new(error: .unknown, message: "SecKeyCopyPublicKey fail")
                        }
                    } else {
                        Fido2Logger.err("SecKeyCreateWithData fail. \(String(describing: error))")
                        throw Fido2Error.new(error: .unknown, message: "SecKeyCreateWithData fail")
                    }
                }catch{
                    Fido2Logger.err("encryptData fail. \(String(describing: error))")
                    throw Fido2Error.new(error: .unknown, details: error)
                }
            }
        }

        // TODO Extension Processing
        let extensions = SimpleOrderedDictionary<String>()
        
        let attestedCredData = AttestedCredentialData(
            aaguid:              LibConfig.aaguid,
            credentialId:        credentialId,
            credentialPublicKey: publicKey
        )
            
        Fido2Logger.debug("<authenticatorMakeCredential> rpEntity.id: \(String(describing: rpEntity.id))")
        Fido2Logger.debug("<authenticatorMakeCredential> rpIdHash source: \(Array(rpEntity.id!.utf8))")
        Fido2Logger.debug("<authenticatorMakeCredential> attestedCredData: \(attestedCredData)")
        let authenticatorData = AuthenticatorData(
            rpIdHash:               SHA256(Array(rpEntity.id!.utf8)).calculate32(),
            userPresent:            (requireUserPresence || requireUserVerification),
            userVerified:           requireUserVerification,
            backupEligibility:      false, //dqj TODO: backupEligibility&backupState support
            backupState:            false,
            signCount:              0, //dqj TODO: support non-zero count
            attestedCredentialData: attestedCredData,
            extensions:             extensions
        )

        guard let attestation = try
            createAttestation(
                authData:       authenticatorData,
                clientDataHash: clientDataHash,
                keyParameter:   keyPara,
                privateKey:     privateKey!
            ) else {
                Fido2Logger.debug("<authenticatorMakeCredential> failed to build attestation object")
                throw Fido2Error(error: .unknown)
        }

        return attestation
    }
    
    public func authenticatorGetAssertion(message: String, rpId: String, clientDataHash: [UInt8], allowCredentialDescriptorList: [PublicKeyCredentialDescriptor], requireUserPresence: Bool, requireUserVerification: Bool, extensions: Dictionary<String, [UInt8]>) async throws -> Optional<AuthenticatorAssertionResult> {
        
        var credSources = try self.gatherCredentialSources(
                rpId:                          rpId,
                allowCredentialDescriptorList: allowCredentialDescriptorList
        )
        if credSources.isEmpty {
            Fido2Logger.debug("<authenticatorGetAssertion> not found allowable credential source")
            throw Fido2Error.new(error: .notAllowed, message: "not found allowable credential source")
        }
        
        //dqj TODO: UI interaction
        try await self.requestUserConsent(message: message)
        
        //dqj TODO: Support processedExtensions
        
        var newSignCount: UInt32 = 0//dqj TODO: Support sign counter
        
        //dqj TODO: select cred & signCount
        let copiedCred = credSources.first
        //copiedCred.signCount = credSources.signCount + counterStep
        //newSignCount = copiedCred.signCount
        //try PlatformAuthenticator.credentialStore.saveCredentialSource(copiedCred!)
        
        let extensions = SimpleOrderedDictionary<String>()

        let authenticatorData = AuthenticatorData(
            rpIdHash:               SHA256(Array(rpId.utf8)).calculate32(), //rpId.bytes.sha256(),
            userPresent:            (requireUserPresence || requireUserVerification),
            userVerified:           requireUserVerification,
            backupEligibility:      false, //dqj TODO: backupEligibility&backupState support
            backupState:            false,
            signCount:              newSignCount,
            attestedCredentialData: nil,
            extensions:             extensions
        )

        let authenticatorDataBytes = try authenticatorData.toBytes()

        var dataToBeSigned = authenticatorDataBytes
        dataToBeSigned.append(contentsOf: clientDataHash)

        guard let attrPub = SecKeyCopyAttributes(copiedCred!.privateKey) as? [CFString: Any],
            let keyType = attrPub[kSecAttrKeyType] as? String else {
            Fido2Logger.err("Fail to get kSecAttrKeyType")
            throw Fido2Error.new(error: .badData, message: "Fail to get kSecAttrKeyType")
        }
        
        if keyType != (kSecAttrKeyTypeRSA as String) {
            throw Fido2Error.new(error: .notSupported, message: "Only support RSA now")
        }
        var alg:SecKeyAlgorithm
        switch(attrPub[kSecAttrKeySizeInBits] as! Int){
        case 256*8:
            alg = .rsaSignatureMessagePKCS1v15SHA256
        case 384*8:
            alg = .rsaSignatureMessagePKCS1v15SHA384
        case 512*8:
            alg = .rsaSignatureMessagePKCS1v15SHA512
        default:
            Fido2Logger.err("Unsupported kSecAttrKeySizeInBits")
            throw Fido2Error.new(error: .notSupported, message: "Unsupported kSecAttrKeySizeInBits")
        }
        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(copiedCred!.privateKey, alg, Data(dataToBeSigned) as CFData, &error)
        if nil != error {
            Fido2Logger.err("SecKeyCreateSignature err: \(String(describing: error))")
            throw Fido2Error.new(error: .notSupported, details: error as! Error)
        }

        let length = CFDataGetLength(signature)
        var rawSign = [UInt8](repeating: 0, count: length)
        CFDataGetBytes(signature, CFRange(location: 0, length: length), &rawSign)
        var assertion = AuthenticatorAssertionResult(
            authenticatorData: authenticatorDataBytes,
            signature:         rawSign
        )

        assertion.userHandle = copiedCred?.userHandle

        if allowCredentialDescriptorList.count != 1 {
            assertion.credentailId = copiedCred!.id
        }
        
        return assertion
    }
    
    public func silentCredentialDiscovery(rpId: String) throws -> [PublicKeyCredentialSource]{
        if !PlatformAuthenticator.enableSilentCredentialDiscovery {
            throw Fido2Error.new(error: .unknown, message: "No SilentCredentialDiscovery feature.")
        }
        return try PlatformAuthenticator.credentialStore.loadAllCredentialSources(rpId: rpId)        
    }
    
    
    private func gatherCredentialSources(
        rpId: String,
        allowCredentialDescriptorList: [PublicKeyCredentialDescriptor]
        ) throws -> [PublicKeyCredentialSource] {
        
        if allowCredentialDescriptorList.isEmpty {
            return try PlatformAuthenticator.credentialStore.loadAllCredentialSources(rpId: rpId)
        } else {
            //Lookup non-resident Credential Source by decrypting Credential ID
            if let pkey = try PlatformAuthenticator.credentialStore.retrieveKey(keyChainId: PlatformAuthenticator.nonResidentSecKeyRP, handle: PlatformAuthenticator.nonResidentSecKeyId) {
                var error: Unmanaged<CFError>?
                for allowCred in allowCredentialDescriptorList{
                    do{
                        let csCBOR = try decryptData(data: Array(Base64.decodeBase64URLTry(allowCred.id) ?? Data()), //Array(allowCred.id.utf8),
                                                     privateKey: SecKeyCreateWithData(pkey as CFData, PlatformAuthenticator.nonResidentSecKeyAlgPara, &error)!,
                                                     encryptDataAlg:PlatformAuthenticator.encryptDataAlg)
                        let credSrc = try PublicKeyCredentialSource.fromCBOR(csCBOR)
                        if nil != credSrc && credSrc!.rpId == rpId {return [credSrc!];}
                    }catch{
                        //Do nothing, try next
                    }
                }
            }
            if !Fido2Core.enabledInsideAuthenticatorResidentStorage() {
                Fido2Logger.info("No non-resident Credential found, we start to try resident Credential. So we may use a Credential that created before you disabling InsideAuthenticatorResidentStorage if auth succ. Calling Fido2Core.clearKeys() can clear all resident Credentials. rpId: \(rpId)")
            }
            
            //Look for resident Credential Source with this Credential ID
            return try allowCredentialDescriptorList.compactMap {
                return try PlatformAuthenticator.credentialStore.lookupCredentialSource(
                    rpId:         rpId,
                    credentialId: Array(Base64.decodeBase64URLTry($0.id) ?? Data())
                )
            }
        }
    }

    // 6.3.1 Lookup Credential Source By Credential ID Algoreithm
    public func lookupCredentialSource(rpId: String, credentialId: [UInt8]) throws
        -> Optional<PublicKeyCredentialSource> {
            Fido2Logger.debug("lookupCredentialSource")
            return try PlatformAuthenticator.credentialStore.lookupCredentialSource(
                rpId:         rpId,
                credentialId: credentialId
            )
    }
    
    public func createAttestation(
        authData:       AuthenticatorData,
        clientDataHash: [UInt8],
        keyParameter:   CFDictionary,
        privateKey:     SecKey
        //CFDic:            COSEAlgorithmIdentifier,
        //keyLabel:       String
        ) throws -> Optional<AttestationObject> {
            var dataToBeSigned = try authData.toBytes()
            dataToBeSigned.append(contentsOf: clientDataHash)
            //Fido2Logger.debug("dataToBeSigned: \(dataToBeSigned)")
            
            var alg:SecKeyAlgorithm
            var algNum: Int64
            switch (keyParameter as NSDictionary)[pnmSelectedAlg] as! COSEAlgorithmIdentifier{
            case COSEAlgorithmIdentifier.rs256:
                alg = .rsaSignatureMessagePKCS1v15SHA256
                algNum = Int64(COSEAlgorithmIdentifier.rs256.rawValue)
            case COSEAlgorithmIdentifier.rs384:
                alg = .rsaSignatureMessagePKCS1v15SHA384
                algNum = Int64(COSEAlgorithmIdentifier.rs384.rawValue)
            case COSEAlgorithmIdentifier.rs512:
                alg = .rsaSignatureMessagePKCS1v15SHA512
                algNum = Int64(COSEAlgorithmIdentifier.rs512.rawValue)
            default:
                Fido2Logger.err("<sign> algorithms not supported \((keyParameter as NSDictionary)[pnmSelectedAlg] ?? "") ")
                throw Fido2Error(error: .notSupported)
            }
            
            Fido2Logger.debug("<createAttestation> SecKeyAlgorithm: \(alg)")
            
            var error: Unmanaged<CFError>?
            let signData = SecKeyCreateSignature(privateKey, alg, Data(dataToBeSigned) as CFData, &error)
            if nil != error {
                Fido2Logger.err("SecKeyCreateSignature err: \(String(describing: error))")
                throw Fido2Error.new(error: .notSupported, details: error as! Error)
            }
                        
            let length = CFDataGetLength(signData)
            var rawData = [UInt8](repeating: 0, count: length)
            CFDataGetBytes(signData, CFRange(location: 0, length: length), &rawData)
            
            //Fido2Logger.debug("<createAttestation> sign: \(rawData)")
            
            let stmt = SimpleOrderedDictionary<String>()
            stmt.addInt("alg", algNum)
            stmt.addBytes("sig", rawData)
            
            return AttestationObject(
                fmt:      "packed", //dqj TODO: support other format?
                authData: authData,
                attStmt:  stmt
            )
    }
    
    private func requestUserConsent(message: String) async throws {
        return try await withCheckedThrowingContinuation { continuation in
            let myContext = LAContext()
            var authError: NSError? = nil
            if myContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError) {
                myContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: message) { (success, evaluateError) in
                    if success {
                        Fido2Logger.debug("<requestUserConsent> succ")
                        continuation.resume()
                    } else {
                        let rtnerr = evaluateError! as NSError
                        let fidoerr = Fido2Error(error:.notAllowed, details:rtnerr)
                        Fido2Logger.debug("<requestUserConsent> fail: \(String(describing: fidoerr))")
                        continuation.resume(throwing: fidoerr)
                    }
                }
            } else {
                Fido2Logger.debug("<requestUserConsent> fail canEvaluatePolicy")
                continuation.resume(throwing: Fido2Error(error:.notSupported, details:authError))
            }
        }
    }
    
}

//MARK: Platform Authenticator Store

public protocol CredentialStore {
    func lookupCredentialSource(rpId: String, credentialId: [UInt8]) throws -> Optional<PublicKeyCredentialSource>
    func saveCredentialSource(_ cred: PublicKeyCredentialSource) throws
    func loadAllCredentialSources(rpId: String) throws -> [PublicKeyCredentialSource]
    func deleteCredentialSource(_ cred: PublicKeyCredentialSource) -> Bool
    func deleteAllCredentialSources(rpId: String, userHandle: [UInt8]) throws
    
    func removeAll(but : [String], rpId : String) throws
}

public class KeychainCredentialStore : CredentialStore {

    public init() {}
    
    public func removeAll(but : [String] = [], rpId: String = "") throws{
        try Keychain.removeAll(ServicePrefix: PlatformAuthenticator.servicePrefix + rpId, but: but)
    }
    
    public func loadAllCredentialSources(rpId: String) throws -> [PublicKeyCredentialSource] {
        let keychain = Keychain(service: PlatformAuthenticator.servicePrefix + rpId)
        let keys = keychain.allKeys()
        return try keys.compactMap {
                if let result = try? keychain.getData($0) {
                    let bytes = result.encodedHexadecimals
                    if 0 < bytes.count {
                        Fido2Logger.debug("<KeychainStore-loadAllCredentialSources> found data for key:\($0)")
                        return try PublicKeyCredentialSource.fromCBOR(bytes)
                    } else {
                        Fido2Logger.debug("<KeychainStore-loadAllCredentialSources> not found data for key:\($0)")
                        return nil
                    }
                } else {
                    Fido2Logger.debug("<KeychainStore-loadAllCredentialSources> failed to load data for key:\($0)")
                    return nil
                }
        }
    }
    
    public func deleteAllCredentialSources(rpId: String, userHandle: [UInt8]) throws{
        try self.loadAllCredentialSources(rpId: rpId, userHandle: userHandle).forEach {
            _ = self.deleteCredentialSource($0)
        }
    }
    
    public func loadAllCredentialSources(rpId: String, userHandle: [UInt8]) throws -> [PublicKeyCredentialSource] {
        return try self.loadAllCredentialSources(rpId: rpId).filter { $0.userHandle.elementsEqual(userHandle) }
    }

    public func lookupCredentialSource(rpId: String, credentialId: [UInt8]) throws
        -> Optional<PublicKeyCredentialSource> {

            let handle = credentialId.hexa
            let keychain = Keychain(service: PlatformAuthenticator.servicePrefix + rpId)

            if let result = try? keychain.getData(handle) {
                let bytes = result.encodedHexadecimals
                if 0 < bytes.count {
                    Fido2Logger.debug("<KeychainStore-lookupCredentialSource> found data for rpId:\(keychain.service) key:\(handle)")
                    return try PublicKeyCredentialSource.fromCBOR(bytes)
                } else {
                    Fido2Logger.debug("<KeychainStore-lookupCredentialSource> not found data for rpId:\(keychain.service) key:\(handle)")
                    return nil
                }
            } else {
                Fido2Logger.debug("<KeychainStore-lookupCredentialSource> failed to load data for rpId:\(keychain.service) key:\(handle)")
                return nil
            }
    }
    
    public func deleteCredentialSource(_ cred: PublicKeyCredentialSource) -> Bool {
        let handle = cred.id
        let keychain = Keychain(service: PlatformAuthenticator.servicePrefix + cred.rpId)
        
        do {
            try keychain.remove(handle.hexa)
            Fido2Logger.debug("<KeychainStore-deleteCredentialSource> deleted data for chain:\(keychain.service) key:\(handle.hexa)")
            return true
        } catch let error {
            Fido2Logger.debug("<KeychainStore-deleteCredentialSource> failed to delete credential-source for chain:\(keychain.service) key:\(handle.hexa): \(error)")
            return false
        }

    }

    public func saveCredentialSource(_ cred: PublicKeyCredentialSource) throws {
        let handle = cred.id
        let keychain = Keychain(service: PlatformAuthenticator.servicePrefix + cred.rpId)

        if let bytes = try cred.toCBOR() {
            do {
                try keychain.set(Data(bytes), key: handle.hexa)
                Fido2Logger.debug("<KeychainStore-saveCredentialSource> saved data for chain:\(keychain.service) key:\(handle.hexa)")
            } catch let error {
                Fido2Logger.debug("<KeychainStore-saveCredentialSource> failed to save credential-source for chain:\(keychain.service) key:\(handle.hexa): \(error)")
                throw Fido2Error.new(error: .unknown, details: error )
            }
        } else {
            throw Fido2Error.new(error: .unknown, message: "cred.toCBOR() fail" )
        }
    }
    
    public func saveKey(keyChainId: String, handle: String, key: Data) throws {

        let keychain = Keychain(service: PlatformAuthenticator.servicePrefix + keyChainId)

        try keychain.set(key, key: handle)
    }
    
    public func retrieveKey(keyChainId: String, handle: String) throws -> Data? {

        let keychain = Keychain(service: PlatformAuthenticator.servicePrefix + keyChainId)

        if let rtn = try keychain.getData(handle) {
            return rtn
        }
        return nil
    }
    
    public func deleteKey(keyChainId: String, handle: String) throws {
        
        let keychain = Keychain(service: PlatformAuthenticator.servicePrefix + keyChainId)
        
        do {
            try keychain.remove(handle)
        } catch let error {
            Fido2Logger.debug("deleteKey fail: \(error)")
            throw Fido2Error.new(error: .unknown, message: "deleteKey fail: \(error)")
        }

    }
}
    
//MARK: Platform Authenticator Crypto support

private func getKeyGeneratePara (requestedAlgorithms: [COSEAlgorithmIdentifier]) throws -> (CFDictionary)  {
    var parameters:CFDictionary?
    for alg in requestedAlgorithms {
        switch alg {
        case COSEAlgorithmIdentifier.rs256:
            parameters = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits as String: 256*8,
                //kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                pnmSelectedAlg: COSEAlgorithmIdentifier.rs256
            ] as CFDictionary
        case COSEAlgorithmIdentifier.rs384:
            parameters = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits as String: 384*8,
                pnmSelectedAlg: COSEAlgorithmIdentifier.rs384
            ] as CFDictionary
        case COSEAlgorithmIdentifier.rs512:
            parameters = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits as String: 512*8,
                pnmSelectedAlg: COSEAlgorithmIdentifier.rs512
            ] as CFDictionary
        default:
            Fido2Logger.debug("<getKeyGeneratePara> not supported alg, try next: \(alg)")
        }
        if parameters != nil {break}
    }
    if parameters != nil {
        Fido2Logger.debug("<getKeyGeneratePara> found supported parameters: \(String(describing: parameters))")
        return parameters!
    }else{
        Fido2Logger.err("<getKeyGeneratePara> all algorithms not supported")
        throw Fido2Error(error: .notSupported)
    }
    
}

private func encryptData(data: [UInt8], publicKey: SecKey, encryptDataAlg: SecKeyAlgorithm) throws -> [UInt8] {
    Fido2Logger.debug("encryptData: \(data)")
    guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, encryptDataAlg) else {
        throw Fido2Error(error: .notSupported)
    }
    var error: Unmanaged<CFError>?
    let enData = SecKeyCreateEncryptedData(publicKey, encryptDataAlg, Data(data) as CFData, &error)
    if nil != error {
        Fido2Logger.debug("<encryptData> fail: \(String(describing: error))")
        throw Fido2Error(error: .notSupported)
    }
    let length = CFDataGetLength(enData)
    var rawData = [UInt8](repeating: 0, count: length)
    CFDataGetBytes(enData, CFRange(location: 0, length: length), &rawData)
    Fido2Logger.debug("encryptData result: \(rawData)")
    return rawData
}

private func decryptData(data: [UInt8], privateKey: SecKey, encryptDataAlg: SecKeyAlgorithm) throws -> [UInt8] {
    Fido2Logger.debug("decryptData: \(data)")
    guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, encryptDataAlg) else {
        throw Fido2Error(error: .notSupported)
    }
    var error: Unmanaged<CFError>?
    let deData = SecKeyCreateDecryptedData(privateKey, encryptDataAlg, Data(data) as CFData, &error)
    if nil != error {
        Fido2Logger.debug("decryptData fail \(String(describing: error))")
        throw Fido2Error.new(error: .unknown, message: "decryptData fail \(String(describing: error))")
    }
    let length = CFDataGetLength(deData)
    var rawData = [UInt8](repeating: 0, count: length)
    CFDataGetBytes(deData, CFRange(location: 0, length: length), &rawData)
    Fido2Logger.debug("decryptData result: \(rawData)")
    return rawData
}
