//
//  JWT.swift
//
//  Created by Antoine Palazzolo on 21/12/20.
//
import Foundation

public protocol CustomHeaderFields: Codable {}
public struct StandardHeaderFields: CustomHeaderFields {}

public protocol CustomPayloadClaims: Codable {}
public struct StandardClaims: CustomPayloadClaims {}

public typealias JWTStandard = JWTCustom<StandardHeaderFields, StandardClaims>
public typealias JWT<T: CustomPayloadClaims> = JWTCustom<StandardHeaderFields, T>

public struct JWTCustom<CustomHeaderFieldsType: CustomHeaderFields, CustomPayloadClaimsType: CustomPayloadClaims>: Codable {
    public let header: Header
    let headerRaw: String
    public let payload: Payload
    let payloadRaw: String
    public let signature: Data
    let signatureRaw: String
    
    public var rawValue: String { "\(self.headerRaw).\(self.payloadRaw).\(self.signatureRaw)" }
    
    public init(string: String) throws {
        let parts = string.components(separatedBy: ".")
        guard parts.count == 3 else { throw DecodingError.invalidTokenStructure }
        let partsData = try parts.map {
            return try Data(base64URLEncoded: $0) ?? { throw DecodingError.invalidBase64URLEncoding }()
        }
        
        let decoder = JSONDecoder()
        self.headerRaw = parts[0]
        self.header = try decoder.decode(Header.self, from: partsData[0])
        
        self.payloadRaw = parts[1]
        self.payload = try decoder.decode(Payload.self, from: partsData[1])
        
        self.signatureRaw = parts[2]
        self.signature = partsData[2]
    }
    
    public init(payload: Payload, signer: Signer? = nil) throws where CustomHeaderFieldsType == StandardHeaderFields {
        let header = Header(algorithm: signer?.algorithm ?? .none, customFields: StandardHeaderFields())
        try self.init(header: header, payload: payload, signer: signer)
    }
    public init(header: Header, payload: Payload, signer: Signer? = nil) throws {
        if header.algorithm != signer?.algorithm ?? .none {
            throw EncodingError.headerAndSignerAlgorithmMismatch
        }
        let encoder = JSONEncoder()
        self.header = header
        self.headerRaw = try encoder.encode(header).base64URLEncodedString()
        self.payload = payload
        self.payloadRaw = try encoder.encode(payload).base64URLEncodedString()
        if let signer = signer {
            let signatureInput = Data("\(self.headerRaw).\(self.payloadRaw)".utf8)
            self.signature = try signer.sign(signatureInput)
            self.signatureRaw = self.signature.base64URLEncodedString()
        } else {
            self.signature = Data()
            self.signatureRaw = ""
        }
    }
    
    public func validateSignature(_ verifier: Verifier) -> Bool {
        let signatureInput = Data("\(self.headerRaw).\(self.payloadRaw)".utf8)
        return verifier.verify(input: signatureInput, signature: self.signature)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(string: container.decode(String.self))
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.rawValue)
    }
}

extension JWTCustom {
    enum DecodingError: Error {
        case invalidTokenStructure
        case invalidHeaderCertificateChain
        case invalidBase64URLEncoding
    }
    enum EncodingError: Error {
        case headerAndSignerAlgorithmMismatch
    }
}

extension JWTCustom {
    @dynamicMemberLookup public struct Header {
        public var algorithm: Algorithm
        public var tokenType: String? = "JWT"
        public var contentType: String?
        public var keyIdentifier: String?
        public var certificateChain: [Data]?
        public var certificateChainURL: URL?
        public var critical: [String]?
        public var customFields: CustomHeaderFieldsType
        
        public init(algorithm: Algorithm, customFields: CustomHeaderFieldsType) {
            self.algorithm = algorithm
            self.tokenType = nil
            self.contentType = nil
            self.keyIdentifier = nil
            self.certificateChain = nil
            self.certificateChainURL = nil
            self.critical = nil
            self.customFields = customFields
        }
        
        public init(algorithm: Algorithm) where CustomHeaderFieldsType == StandardHeaderFields {
            self.init(algorithm: algorithm, customFields: StandardHeaderFields())
        }
        
        public subscript<T>(dynamicMember member: WritableKeyPath<CustomHeaderFieldsType, T>) -> T {
            get {
                return self.customFields[keyPath: member]
            }
            set {
                self.customFields[keyPath: member] = newValue
            }
        }
    }
}
extension JWTCustom {
    @dynamicMemberLookup public struct Payload {
        public var issuer: String?
        public var subject: String?
        public var audience: [String]?
        public var expirationTime: Date?
        public var notBefore: Date?
        public var issuedAt: Date?
        public var tokenIdentifier: String?
        public var customClaims: CustomPayloadClaimsType
        
        public init(customClaims: CustomPayloadClaimsType) {
            self.issuer = nil
            self.subject = nil
            self.audience = nil
            self.expirationTime = nil
            self.notBefore = nil
            self.issuedAt = nil
            self.tokenIdentifier = nil
            self.customClaims = customClaims
        }
        
        public init() where CustomPayloadClaimsType == StandardClaims {
            self.init(customClaims: StandardClaims())
        }
        
        public subscript<T>(dynamicMember member: WritableKeyPath<CustomPayloadClaimsType, T>) -> T {
            get {
                return self.customClaims[keyPath: member]
            }
            set {
                self.customClaims[keyPath: member] = newValue
            }
        }
    }
}

extension JWTCustom.Header: Codable {
    enum CodingKeys: String, CodingKey {
        case algorithm = "alg"
        case tokenType = "typ"
        case contentType = "cty"
        case keyIdentifier = "kid"
        case certificateChain = "x5c"
        case certificateChainURL = "x5u"
        case critical = "crit"
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.algorithm = try container.decode(Algorithm.self, forKey: .algorithm)
        self.tokenType = try container.decodeIfPresent(String.self, forKey: .tokenType)
        self.contentType = try container.decodeIfPresent(String.self, forKey: .contentType)
        self.keyIdentifier = try container.decodeIfPresent(String.self, forKey: .keyIdentifier)
        self.certificateChain = try container.decodeIfPresent([String].self, forKey: .certificateChain)?.map {
            guard let data = Data(base64Encoded: $0) else { throw JWTCustom.DecodingError.invalidHeaderCertificateChain }
            return data
        }
        self.certificateChainURL = try container.decodeIfPresent(URL.self, forKey: .certificateChainURL)
        self.critical = try container.decodeIfPresent([String].self, forKey: .critical)
        self.customFields = try CustomHeaderFieldsType(from: decoder)
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.algorithm, forKey: .algorithm)
        try container.encodeIfPresent(self.tokenType, forKey: .tokenType)
        try container.encodeIfPresent(self.contentType, forKey: .contentType)
        try container.encodeIfPresent(self.keyIdentifier, forKey: .keyIdentifier)
        try container.encodeIfPresent(self.certificateChain?.map({ $0.base64EncodedString() }), forKey: .certificateChain)
        try container.encodeIfPresent(self.certificateChainURL, forKey: .certificateChainURL)
        try container.encodeIfPresent(self.critical, forKey: .critical)
        try self.customFields.encode(to: encoder)
    }
    
}
extension JWTCustom.Payload: Codable {
    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case expirationTime = "exp"
        case notBefore = "nbf"
        case issuedAt = "iat"
        case tokenIdentifier = "jti"
    }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.issuer = try container.decodeIfPresent(String.self, forKey: .issuer)
        self.subject = try container.decodeIfPresent(String.self, forKey: .subject)
        do {
            self.audience = try container.decodeIfPresent([String].self, forKey: .audience)
        } catch {
            self.audience = try container.decodeIfPresent(String.self, forKey: .audience).map { [$0] }
        }
        self.expirationTime = try container.decodeIfPresent(Double.self, forKey: .expirationTime).map {
            Date(timeIntervalSince1970: $0)
        }
        self.notBefore = try container.decodeIfPresent(Double.self, forKey: .notBefore).map {
            Date(timeIntervalSince1970: $0)
        }
        self.issuedAt = try container.decodeIfPresent(Double.self, forKey: .issuedAt).map {
            Date(timeIntervalSince1970: $0)
        }
        self.tokenIdentifier = try container.decodeIfPresent(String.self, forKey: .tokenIdentifier)
        self.customClaims = try CustomPayloadClaimsType(from: decoder)
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(self.issuer, forKey: .issuer)
        try container.encodeIfPresent(self.subject, forKey: .subject)
        try container.encodeIfPresent(self.audience, forKey: .audience)
        let expiration = (self.expirationTime?.timeIntervalSince1970).map(Int64.init)
        try container.encodeIfPresent(expiration, forKey: .expirationTime)
        let notBefore = (self.notBefore?.timeIntervalSince1970).map(Int64.init)
        try container.encodeIfPresent(notBefore, forKey: .notBefore)
        let issuedAt = (self.issuedAt?.timeIntervalSince1970).map(Int64.init)
        try container.encodeIfPresent(issuedAt, forKey: .issuedAt)
        try container.encodeIfPresent(self.tokenIdentifier, forKey: .tokenIdentifier)
        try self.customClaims.encode(to: encoder)
    }
}
