//
//  ECKey.swift
//  
//
//  Created by Antoine Palazzolo on 24/12/2020.
//

import Foundation

// A namespace EC keys
public enum ECKey {
    
    public struct Public: PublicKey {
        var secKey: SecKey
        public init(secKey: SecKey) throws {
            if secKey.isECKey {
                self.secKey = secKey
            } else {
                throw NSError(osStatus: errSecInvalidAttributeKeyType)
            }
        }
        
        // ANSI X9.63 standard formatted key data
        public init(x963Key data: Data) throws {
            self.secKey = try SecKey.keyFromExternalRepresentation(data, type: kSecAttrKeyTypeEC, class: kSecAttrKeyClassPublic)
        }
    }
    public struct Private: PrivateKey {
        var secKey: SecKey
        public init(secKey: SecKey) throws {
            if secKey.isECKey {
                self.secKey = secKey
            } else {
                throw NSError(osStatus: errSecInvalidAttributeKeyType)
            }
        }
        // ANSI X9.63 standard formatted key data
        public init(x963Key data: Data) throws {
            self.secKey = try SecKey.keyFromExternalRepresentation(data, type: kSecAttrKeyTypeEC, class: kSecAttrKeyClassPrivate)
        }
    }
    
    public static func keysFromPKCS12Identity(_ p12Data: Data, passphrase: String) throws -> (Public, Private) {
        return try SecKey.keysFromPKCS12Identity(p12Data, passphrase: passphrase)
    }
}

