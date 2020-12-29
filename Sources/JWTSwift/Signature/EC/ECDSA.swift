//
//  ECDSA.swift
//  
//
//  Created by Antoine Palazzolo on 24/12/2020.
//

import Foundation

public struct ECDSASigner: Signer, SecKeySignature {
    enum ECSignerError: Error {
        case invalidSignaturePairSize
    }
    public var algorithm: Algorithm {
        switch self.hashFunction {
        case .sha256: return .ecdsa_256
        case .sha384: return .ecdsa_384
        case .sha512: return .ecdsa_512
        }
    }
    
    public let hashFunction: HashFunction
    public let privateKey: ECKey.Private
    
    var secKey: SecKey { self.privateKey.secKey }
    var secKeyAlgorithm: SecKeyAlgorithm { SecKeyAlgorithm.ecdsaSignatureMessageX962(hashFunction: self.hashFunction) }
    
    public init(hashFunction: HashFunction, privateKey: ECKey.Private) {
        self.hashFunction = hashFunction
        self.privateKey = privateKey
    }
    
    public func sign(_ input: Data) throws -> Data {
        let signature = try self.generateSignature(input)
        let decoder = DERDecoder()
        let node = try decoder.decode(data: signature)
        let decodedSignature = try node.children.reduce(into: Data()) { (result, node) in
            var data = node.data
            data.removeASN1NonNegativeLeadingByteIfNeeded()
            if data.count != self.secKey.size {
                throw ECSignerError.invalidSignaturePairSize
            }
            result.append(data)
        }
        return decodedSignature
    }
}

public struct ECDSAVerifier: Verifier, SecKeySignature {
    public let hashFunction: HashFunction
    public let publicKey: ECKey.Public
    
    var secKey: SecKey { return self.publicKey.secKey }
    var secKeyAlgorithm: SecKeyAlgorithm { SecKeyAlgorithm.ecdsaSignatureMessageX962(hashFunction: self.hashFunction) }
    
    public init(hashFunction: HashFunction, publicKey: ECKey.Public) {
        self.hashFunction = hashFunction
        self.publicKey = publicKey
    }
    
    public func verify(input: Data, signature: Data) -> Bool {
        if signature.count != self.secKey.size * 2 { return false }
        let splitIndex = signature.startIndex.advanced(by: signature.count/2)
        var r = signature[signature.startIndex..<splitIndex]
        r.addASN1NonNegativeLeadingByteIfNeeded()
        var s = signature[splitIndex..<signature.endIndex]
        s.addASN1NonNegativeLeadingByteIfNeeded()
        do {
            let node = DERDecoder.Construct(universalTagClassNumber: .sequence, content: [
                DERDecoder.Primitive(universalTagClassNumber: .integer, data: r),
                DERDecoder.Primitive(universalTagClassNumber: .integer, data: s)
            ])
            return try self.verifySignature(input: input, signature: node.encoded())
        } catch {
            return false
        }
    }
}

//add or remove the leading 0x00 byte that indicate non negative ASN1 integer if the second byte begin with 1
private extension Data {
    private static let negativeIntegerMask: UInt8 = 0b1000_0000
    mutating func addASN1NonNegativeLeadingByteIfNeeded() {
        if self.isEmpty { return }
        if self[self.startIndex] & Self.negativeIntegerMask == Self.negativeIntegerMask {
            self.insert(0x00, at: self.startIndex)
        }
    }
    mutating func removeASN1NonNegativeLeadingByteIfNeeded() {
        if self.count < 2 { return }
        let firstIndex = self.startIndex
        let secondIndex = firstIndex.advanced(by: 1)
        if self[firstIndex] == 0x00 && self[secondIndex] & Self.negativeIntegerMask == Self.negativeIntegerMask  {
            self.removeFirst()
        }
    }
}

fileprivate extension SecKeyAlgorithm {
    static func ecdsaSignatureMessageX962(hashFunction: HashFunction) -> SecKeyAlgorithm {
        switch hashFunction {
        case .sha256:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        case .sha384:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
        case .sha512:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512
        }
    }
}
