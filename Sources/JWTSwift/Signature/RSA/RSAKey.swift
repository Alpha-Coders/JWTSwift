//
//  RSAKey.swift
//  
//
//  Created by Antoine Palazzolo on 23/12/2020.
//

import Foundation
import Security

// A namespace RSA keys
public enum RSAKey {
    
    public struct Public: PublicKey {
        var secKey: SecKey
        public init(secKey: SecKey) throws {
            if secKey.isRSAKey {
                self.secKey = secKey
            } else {
                throw NSError(osStatus: errSecInvalidAttributeKeyType)
            }
        }
        
        //PKCS #1 formatted key data
        public init(pkcs1Key data: Data) throws {
            try self.init(secKey: SecKey.keyFromExternalRepresentation(data, type: kSecAttrKeyTypeRSA, class: kSecAttrKeyClassPublic))
        }
    }
    public struct Private: PrivateKey {
        var secKey: SecKey
        public init(secKey: SecKey) throws {
            if secKey.isRSAKey {
                self.secKey = secKey
            } else {
                throw NSError(osStatus: errSecInvalidAttributeKeyType)
            }
        }
        //PKCS #1 formatted key data
        public init(pkcs1Key data: Data) throws {
            try self.init(secKey: SecKey.keyFromExternalRepresentation(data, type: kSecAttrKeyTypeRSA, class: kSecAttrKeyClassPrivate))
        }
    }
    
    public static func keysFromPKCS12Identity(_ p12Data: Data, passphrase: String) throws -> (Public, Private) {
        return try SecKey.keysFromPKCS12Identity(p12Data, passphrase: passphrase)
    }
}

