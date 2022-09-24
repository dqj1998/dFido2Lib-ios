//
//  WAKTypes.swift
//  WebAuthnKit
//
//  Created by Lyo Kato on 2018/11/20.
//  Copyright © 2018 Lyo Kato. All rights reserved.
//

import Foundation

public enum WAKError : Error {
    case badData
    case badOperation
    case invalidState
    case constraint
    case cancelled
    case timeout
    case notAllowed
    case unsupported
    case unknown
}

public enum WAKResult<T, Error: Swift.Error> {
    case success(T)
    case failure(Error)
}

public enum PublicKeyCredentialType: String, Codable {
    case publicKey = "public-key"
}

public enum UserVerificationRequirement: String, Codable {

    case required
    case preferred
    case discouraged

    public static func ==(
        lhs: UserVerificationRequirement,
        rhs: UserVerificationRequirement) -> Bool {

        switch (lhs, rhs) {
        case (.required, .required):
            return true
        case (.preferred, .preferred):
            return true
        case (.discouraged, .discouraged):
            return true
        default:
            return false
        }

    }
}

//dqj
public enum ResidentKey: String, Codable {

    case required
    case preferred
    case discouraged

    public static func ==(
        lhs: ResidentKey,
        rhs: ResidentKey) -> Bool {

        switch (lhs, rhs) {
        case (.required, .required):
            return true
        case (.preferred, .preferred):
            return true
        case (.discouraged, .discouraged):
            return true
        default:
            return false
        }

    }
}

public protocol AuthenticatorResponse : Codable {}
public struct AuthenticatorAttestationResponse : AuthenticatorResponse {
    public var clientDataJSON: String
    public var attestationObject: String
}

public struct AuthenticatorAssertionResponse: AuthenticatorResponse {
    public var clientDataJSON: String
    public var authenticatorData: String
    public var signature: String
    public var userHandle: String?
}

public struct PublicKeyCredential<T: AuthenticatorResponse>: Codable {
    public var type: PublicKeyCredentialType = .publicKey
    public var rawId: String //[UInt8]
    public var id: String
    public var authenticatorAttachment: AuthenticatorAttachment?
    public var response: T   
    
    // public func getClientExtensionResults(){}
    
    public func toJSON() -> Optional<String> {
       return JSONHelper<PublicKeyCredential<T>>.encode(self)
    }
    
    //TODO: Use this method
    public func isConditionalMediationAvailable() -> Bool{
        return true;
    }
}

public enum AuthenticatorTransport: String, Codable, Equatable {
    case usb
    case nfc
    case ble
    case internal_ = "internal"

    public static func ==(
        lhs: AuthenticatorTransport,
        rhs: AuthenticatorTransport) -> Bool {

        switch (lhs, rhs) {
        case (.usb, .usb):
            return true
        case (.nfc, .nfc):
            return true
        case (.ble, .ble):
            return true
        case (.internal_, .internal_):
            return true
        default:
            return false
        }
    }
}

public struct PublicKeyCredentialDescriptor: Codable {
    
    public var type: PublicKeyCredentialType = .publicKey
    public var id: String // base64 credential ID
    public var transports: [String]? //dqj [AuthenticatorTransport]
    
    public init(
        id:         String                  = "",
        transports: [String] = [String]()//dqj [AuthenticatorTransport] = [AuthenticatorTransport]()
    ) {
        self.id         = id
        self.transports = transports
    }

    //dqj
    /*public mutating func addTransport(transport: AuthenticatorTransport) {
       self.transports.append(transport)
    }*/
    public mutating func addTransport(transport: String) {
       self.transports?.append(transport)
    }
}

public struct PublicKeyCredentialRpEntity: Codable {
    
    public var id: String?
    public var name: String
    public var icon: String?
    
    public init(
        id: String? = nil,
        name: String = "",
        icon: String? = nil
    ) {
        self.id   = id
        self.name = name
        self.icon = icon
    }
}

public struct PublicKeyCredentialUserEntity: Codable {
    
    public var id: String//dqj [Uint8]
    public var displayName: String
    public var name: String
    public var icon: String?
    
    public init(
        //id: [UInt8] = [UInt8](),
        id: String = "",
        displayName: String = "",
        name: String = "",
        icon: String? = nil
    ) {
        self.id = id
        self.displayName = displayName
        self.name = name
        self.icon = icon
    }
}

public enum AttestationConveyancePreference: String, Codable {
    case none
    case direct
    case indirect
    case enterprise //dqj

    public static func ==(
        lhs: AttestationConveyancePreference,
        rhs: AttestationConveyancePreference) -> Bool {

        switch (lhs, rhs) {
        case (.none, .none):
            return true
        case (.direct, .direct):
            return true
        case (.indirect, .indirect):
            return true
        case (.enterprise, .enterprise):
            return true
        default:
            return false
        }
    }
}

public struct PublicKeyCredentialParameters : Codable {
    public var type: PublicKeyCredentialType = .publicKey
    private var alg: Int //COSEAlgorithmIdentifier
    
    public init(alg: Int) {
        self.alg = alg
    }
    
    public func getCOSEAlgorithmIdentifier() -> COSEAlgorithmIdentifier{
        return COSEAlgorithmIdentifier.fromInt(alg) ?? COSEAlgorithmIdentifier.other
    }
}

public enum TokenBindingStatus: String, Codable {

    case present
    case supported

    public static func ==(
        lhs: TokenBindingStatus,
        rhs: TokenBindingStatus) -> Bool{

        switch (lhs, rhs) {
        case (.present, .present):
            return true
        case (.supported, .supported):
            return true
        default:
            return false
        }
    }
}

public struct TokenBinding: Codable {
    public var status: TokenBindingStatus
    public var id: String
    
    public init(id: String, status: TokenBindingStatus) {
        self.id = id
        self.status = status
    }
}

public enum CollectedClientDataType: String, Codable {
    case webAuthnCreate = "webauthn.create"
    case webAuthnGet = "webauthn.get"
}

public struct CollectedClientData : Codable {
    public var type: CollectedClientDataType
    public var challenge: String // Must be String according to spec
    public var origin: String
    public var tokenBinding: TokenBinding?
}

public enum AuthenticatorAttachment: String, Codable {
    case platform
    case crossPlatform = "cross-platform"

    public static func ==(
        lhs: AuthenticatorAttachment,
        rhs: AuthenticatorAttachment) -> Bool {
        switch (lhs, rhs) {
        case (.platform, .platform):
            return true
        case (.crossPlatform, .crossPlatform):
            return true
        default:
            return false
        }
    }
}

public struct AuthenticatorSelectionCriteria: Codable {
    
    public var authenticatorAttachment: AuthenticatorAttachment?
    public var requireResidentKey: Bool?
    public var userVerification: UserVerificationRequirement
    public var residentKey: ResidentKey?
    
    public init(
        authenticatorAttachment: AuthenticatorAttachment? = nil,
        requireResidentKey: Bool = true,
        userVerification: UserVerificationRequirement = .preferred,
        residentKey: ResidentKey = .required
    ) {
        self.authenticatorAttachment = authenticatorAttachment
        self.requireResidentKey = requireResidentKey
        self.userVerification = userVerification
        self.residentKey = residentKey
    }
}

// put extensions supported in this library
public struct ExtensionOptions: Codable {

}

public struct PublicKeyCredentialCreationOptions: Codable {
    
    public var rp: PublicKeyCredentialRpEntity
    public var user: PublicKeyCredentialUserEntity
    public var challenge: String
    public var pubKeyCredParams: [PublicKeyCredentialParameters]
    public var timeout: UInt64?
    public var excludeCredentials: [PublicKeyCredentialDescriptor]?
    public var authenticatorSelection: AuthenticatorSelectionCriteria?
    public var attestation: AttestationConveyancePreference
    public var extensions: ExtensionOptions?
    
    public init(
        rp: PublicKeyCredentialRpEntity = PublicKeyCredentialRpEntity(),
        user: PublicKeyCredentialUserEntity = PublicKeyCredentialUserEntity(),
        challenge: String = "",
        pubKeyCredParams: [PublicKeyCredentialParameters] = [PublicKeyCredentialParameters](),
        timeout: UInt64? = nil,
        excludeCredentials: [PublicKeyCredentialDescriptor] = [PublicKeyCredentialDescriptor](),
        authenticatorSelection: AuthenticatorSelectionCriteria? = nil,
        attestation: AttestationConveyancePreference = .none
    ) {
        self.rp = rp
        self.user = user
        self.challenge = challenge
        self.pubKeyCredParams = pubKeyCredParams
        self.timeout = timeout
        self.excludeCredentials = excludeCredentials
        self.authenticatorSelection = authenticatorSelection
        self.attestation = attestation
        // not supported yet
        self.extensions = nil
    }
    
    public mutating func addPubKeyCredParam(alg: COSEAlgorithmIdentifier) {
        self.pubKeyCredParams.append(PublicKeyCredentialParameters(alg: alg.rawValue))
    }
    
    public func toJSON() -> Optional<String> {
        let obj = PublicKeyCredentialCreationArgs(publicKey: self)
        return JSONHelper<PublicKeyCredentialCreationArgs>.encode(obj)
    }
    
    public static func fromJSON(json: String) -> Optional<PublicKeyCredentialCreationOptions> {
        guard let args = JSONHelper<PublicKeyCredentialCreationArgs>.decode(json) else {
            return nil
        }
        return args.publicKey
    }
}

//dqj added
public enum CredentialMediationRequirement: String, Codable {
    case silent =  "silent"
    case optional = "optional"
    case conditional = "conditional"
    case required = "required"
}


public struct PublicKeyCredentialRequestOptions: Codable {
    public var challenge: String
    public var rpId: String?
    public var allowCredentials: [PublicKeyCredentialDescriptor]?
    public var userVerification: UserVerificationRequirement?
    public var timeout: UInt64?
    public var mediation: CredentialMediationRequirement? //dqj
    // let extensions: []
    
    public init(
        challenge: String,
        rpId: String = "",
        allowCredentials: [PublicKeyCredentialDescriptor] = [PublicKeyCredentialDescriptor](),
        userVerification: UserVerificationRequirement = .preferred,
        timeout: UInt64? = nil
    ) {
        self.challenge = challenge
        self.rpId = rpId
        self.allowCredentials = allowCredentials
        self.userVerification = userVerification
        self.timeout = timeout
    }
    
    public mutating func addAllowCredential(
        credentialId: String,
        transports: [String]//dqj [AuthenticatorTransport]
    ) {
        if (self.allowCredentials == nil) {
            self.allowCredentials = []
        }
        self.allowCredentials?.append(PublicKeyCredentialDescriptor(
            id:         credentialId, //String(bytes: credentialId, encoding: .utf8)!,
            transports: transports
        ))
    }
    
    public func toJSON() -> Optional<String> {
        let obj = PublicKeyCredentialRequestArgs(publicKey: self)
        return JSONHelper<PublicKeyCredentialRequestArgs>.encode(obj)
    }
    
    public static func fromJSON(json: String) -> Optional<PublicKeyCredentialRequestOptions> {
        guard let args = JSONHelper<PublicKeyCredentialRequestArgs>.decode(json) else {
            return nil
        }
        return args.publicKey
    }
}

public struct PublicKeyCredentialCreationArgs: Codable {
    public let publicKey: PublicKeyCredentialCreationOptions
}

public struct PublicKeyCredentialRequestArgs: Codable {
    public let publicKey: PublicKeyCredentialRequestOptions
}
