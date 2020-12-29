//
//  RSASSA_PKCS1.swift
//  
//
//  Created by Antoine Palazzolo on 23/12/2020.
//

import Foundation
import Security

public struct RSASSA_PKCS1Signer: Signer, SecKeySignature {
    public var algorithm: Algorithm {
        switch self.hashFunction {
        case .sha256: return .rsassa_pkcs1_256
        case .sha384: return .rsassa_pkcs1_384
        case .sha512: return .rsassa_pkcs1_512
        }
    }
    
    public let hashFunction: HashFunction
    public let privateKey: RSAKey.Private
    
    var secKey: SecKey { self.privateKey.secKey }
    var secKeyAlgorithm: SecKeyAlgorithm { SecKeyAlgorithm.rsaSignatureMessagePKCS1v15(hashFunction: self.hashFunction) }
    
    public init(hashFunction: HashFunction, privateKey: RSAKey.Private) {
        self.hashFunction = hashFunction
        self.privateKey = privateKey
    }
    
    public func sign(_ input: Data) throws -> Data {
        return try self.generateSignature(input)
    }
}

public struct RSASSA_PKCS1Verifier: Verifier, SecKeySignature {
    public let hashFunction: HashFunction
    public let publicKey: RSAKey.Public
    
    var secKey: SecKey { return self.publicKey.secKey }
    var secKeyAlgorithm: SecKeyAlgorithm { SecKeyAlgorithm.rsaSignatureMessagePKCS1v15(hashFunction: self.hashFunction) }

    public init(hashFunction: HashFunction, publicKey: RSAKey.Public) {
        self.hashFunction = hashFunction
        self.publicKey = publicKey
    }
    
    public func verify(input: Data, signature: Data) -> Bool {
        return self.verifySignature(input: input, signature: signature)
    }
}

fileprivate extension SecKeyAlgorithm {
    static func rsaSignatureMessagePKCS1v15(hashFunction: HashFunction) -> SecKeyAlgorithm {
        switch hashFunction {
        case .sha256:
            return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        case .sha384:
            return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA384
        case .sha512:
            return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512
        }
    }
}
