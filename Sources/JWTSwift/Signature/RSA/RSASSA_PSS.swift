//
//  RSASSA_PSS.swift
//  
//
//  Created by Antoine Palazzolo on 24/12/2020.
//

import Foundation
import Security

public struct RSASSA_PSSSigner: Signer, SecKeySignature {
    public var algorithm: Algorithm {
        switch self.hashFunction {
        case .sha256: return .rsassa_pss_256
        case .sha384: return .rsassa_pss_384
        case .sha512: return .rsassa_pss_512
        }
    }
    
    public let hashFunction: HashFunction
    public let privateKey: RSAKey.Private
    
    var secKey: SecKey { self.privateKey.secKey }
    var secKeyAlgorithm: SecKeyAlgorithm { SecKeyAlgorithm.rsaSignatureMessagePSS(hashFunction: self.hashFunction) }
    
    public init(hashFunction: HashFunction, privateKey: RSAKey.Private) {
        self.hashFunction = hashFunction
        self.privateKey = privateKey
    }
    
    public func sign(_ input: Data) throws -> Data {
        return try self.generateSignature(input)
    }
}

public struct RSASSA_PSSVerifier: Verifier, SecKeySignature {
    public let hashFunction: HashFunction
    public let publicKey: RSAKey.Public
    
    var secKey: SecKey { return self.publicKey.secKey }
    var secKeyAlgorithm: SecKeyAlgorithm { SecKeyAlgorithm.rsaSignatureMessagePSS(hashFunction: self.hashFunction) }
    
    public init(hashFunction: HashFunction, publicKey: RSAKey.Public) {
        self.hashFunction = hashFunction
        self.publicKey = publicKey
    }
    
    public func verify(input: Data, signature: Data) -> Bool {
        return self.verifySignature(input: input, signature: signature)
    }
}

fileprivate extension SecKeyAlgorithm {
    static func rsaSignatureMessagePSS(hashFunction: HashFunction) -> SecKeyAlgorithm {
        switch hashFunction {
        case .sha256:
            return SecKeyAlgorithm.rsaSignatureMessagePSSSHA256
        case .sha384:
            return SecKeyAlgorithm.rsaSignatureMessagePSSSHA384
        case .sha512:
            return SecKeyAlgorithm.rsaSignatureMessagePSSSHA512
        }
    }
}
