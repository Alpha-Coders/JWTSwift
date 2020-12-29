//
//  HMAC.swift
//  
//
//  Created by Antoine Palazzolo on 23/12/2020.
//

import Foundation
import CryptoKit

public struct HMACSignature: Signer, Verifier {
    public var hashFunction: HashFunction
    public var secret: Data

    public var algorithm: Algorithm {
        switch self.hashFunction {
        case .sha256: return .hmac_256
        case .sha384: return .hmac_384
        case .sha512: return .hmac_512
        }
    }
    
    public init(hashFunction: HashFunction, secret: String) {
        self.init(hashFunction: hashFunction, secret: Data(secret.utf8))
    }
    
    public init(hashFunction: HashFunction, secret: Data) {
        self.hashFunction = hashFunction
        self.secret = secret
    }
    
    public func sign(_ input: Data) -> Data {
        let key = SymmetricKey(data: secret)
        
        switch self.hashFunction {
        case .sha256: return Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
        case .sha384: return Data(HMAC<SHA384>.authenticationCode(for: input, using: key))
        case .sha512: return Data(HMAC<SHA512>.authenticationCode(for: input, using: key))
        }
    }
    
    public func verify(input: Data, signature: Data) -> Bool {
        return self.sign(input) == signature
    }
}
