//
//  Signature.swift
//  
//
//  Created by Antoine Palazzolo on 23/12/2020.
//

import Foundation

public protocol Signer {
    var algorithm: Algorithm { get }
    func sign(_ input: Data) throws -> Data
}

public protocol Verifier {
    func verify(input: Data, signature: Data) -> Bool
}
