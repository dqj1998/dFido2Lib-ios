//
//  COSE.swift
//  WebAuthnKit
//
//  Created by Lyo Kato on 2018/11/20.
//  Edit by dqj on 2022/09/03
//  Copyright © 2018 Lyo Kato. All rights reserved.
//

import Foundation

internal struct COSEKeyFieldType {
    static let kty:    Int =  1
    static let alg:    Int =  3
    static let crv:    Int = -1
    static let xCoord: Int = -2
    static let yCoord: Int = -3
    static let n:      Int = -1
    static let e:      Int = -2
}

internal struct COSEKeyCurveType {
    static let p256:    Int = 1
    static let p384:    Int = 2
    static let p521:    Int = 3
    static let x25519:  Int = 4
    static let x448:    Int = 5
    static let ed25519: Int = 6
    static let ed448:   Int = 7
}

internal struct COSEKeyType {
    static let ec2: UInt8 = 2
    static let rsa: UInt8 = 3
}

public enum COSEAlgorithmIdentifier: Int, Codable {
    // See https://www.iana.org/assignments/cose/cose.xhtml#algorithms

    case rs256 = -257
    case rs384 = -258
    case rs512 = -259
    case es256 =   -7
    case es384 =  -35
    case es512 =  -36
    case ed256 = -260
    case ed512 = -261
    case ps256 =  -37
    
    case other = 0
    
    public static func fromInt(_ num: Int) -> Optional<COSEAlgorithmIdentifier> {
        switch num {
        case self.rs256.rawValue:
            return self.rs256
        case self.rs384.rawValue:
            return self.rs384
        case self.rs512.rawValue:
            return self.rs512
        case self.es256.rawValue:
            return self.es256
        case self.es384.rawValue:
            return self.es384
        case self.es512.rawValue:
            return self.es512
        case self.ed256.rawValue:
            return self.ed256
        case self.ed512.rawValue:
            return self.ed512
        case self.ps256.rawValue:
            return self.ps256
        default:
            return other
        }
    }

    public static func ==(
        lhs: COSEAlgorithmIdentifier,
        rhs: COSEAlgorithmIdentifier) -> Bool {

        switch (lhs, rhs) {
        case (.es256, .es256):
            return true
        case (.es384, .es384):
            return true
        case (.es512, .es512):
            return true
        case (.rs256, .rs256):
            return true
        case (.rs384, .rs384):
            return true
        case (.rs512, .rs512):
            return true
        case (.ed256, .ed256):
            return true
        case (.ed512, .ed512):
            return true
        case (.ps256, .ps256):
            return true
        default:
            return false
        }

    }
}


