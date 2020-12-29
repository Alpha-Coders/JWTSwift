//
//  Algorithm.swift
//  
//
//  Created by Antoine Palazzolo on 22/12/2020.
//

import Foundation

public struct Algorithm: RawRepresentable, Equatable, Codable {
    public var rawValue: String
    public init(rawValue: String) {
        self.rawValue = rawValue
    }
}

extension Algorithm {
    public static let none = Algorithm(rawValue: "none")
    
    public static let hmac_256 = Algorithm(rawValue: "HS256")
    public static let hmac_384 = Algorithm(rawValue: "HS384")
    public static let hmac_512 = Algorithm(rawValue: "HS512")
    
    public static let rsassa_pkcs1_256 = Algorithm(rawValue: "RS256")
    public static let rsassa_pkcs1_384 = Algorithm(rawValue: "RS384")
    public static let rsassa_pkcs1_512 = Algorithm(rawValue: "RS512")
    
    public static let ecdsa_256 = Algorithm(rawValue: "ES256")
    public static let ecdsa_384 = Algorithm(rawValue: "ES384")
    public static let ecdsa_512 = Algorithm(rawValue: "ES512")
    
    public static let rsassa_pss_256 = Algorithm(rawValue: "PS256")
    public static let rsassa_pss_384 = Algorithm(rawValue: "PS384")
    public static let rsassa_pss_512 = Algorithm(rawValue: "PS512")
}
