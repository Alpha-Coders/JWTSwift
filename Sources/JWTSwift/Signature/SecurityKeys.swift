//
//  SecurityKeys.swift
//  
//
//  Created by Antoine Palazzolo on 24/12/2020.
//

import Foundation
import Security

public protocol PublicKey {
    init(secKey: SecKey) throws
    init(secCertificate cert: SecCertificate) throws
    init(certificateData data: Data) throws
}

extension PublicKey {
    public init(secCertificate cert: SecCertificate) throws {
        if let key = SecCertificateCopyKey(cert) {
            try self.init(secKey: key)
        } else {
            throw NSError(osStatus: errSecInvalidValue)
        }
    }
    //init from a DER representation of a certificate.
    public init(certificateData data: Data) throws {
        if let cert = SecCertificateCreateWithData(nil, data as CFData) {
            try self.init(secCertificate: cert)
        } else {
            throw NSError(osStatus: errSecInvalidValue)
        }
    }
}

public protocol PrivateKey {
    init(secKey: SecKey) throws
}

extension SecKey {
    static func keysFromPKCS12Identity<PublicKeyType: PublicKey, PrivateKeyType: PrivateKey>(_ p12Data: Data, passphrase: String) throws -> (PublicKeyType, PrivateKeyType) {
        var importResult : CFArray? = nil
        let importParam = [kSecImportExportPassphrase as String: passphrase]
        let status = SecPKCS12Import(p12Data as CFData, importParam as CFDictionary, &importResult)
        
        guard status == errSecSuccess else { throw NSError(osStatus: status) }
        
        let result: (PublicKeyType, PrivateKeyType)
        if let array = importResult.map({ unsafeBitCast($0, to: NSArray.self) }),
           let content = array.firstObject as? NSDictionary,
           let identity = (content[kSecImportItemIdentity as String] as! SecIdentity?) {
            
            var privateKeyResult: SecKey? = nil
            var certificateResult: SecCertificate? = nil
            let status = (
                SecIdentityCopyPrivateKey(identity, &privateKeyResult),
                SecIdentityCopyCertificate(identity, &certificateResult)
            )
            guard status.0 == errSecSuccess else { throw NSError(osStatus: status.0) }
            guard status.1 == errSecSuccess else { throw NSError(osStatus: status.1) }
            if let privateKey = try privateKeyResult.map(PrivateKeyType.init),
               let publicKey = try certificateResult.flatMap(PublicKeyType.init) {
                result = (publicKey, privateKey)
            } else {
                throw NSError(osStatus: errSecMissingValue)
            }
        } else {
            throw NSError(osStatus: errSecMissingValue)
        }
        return result
    }
    static func keyFromExternalRepresentation(_ data: Data, type: CFString, class: CFString) throws -> SecKey {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: type,
            kSecAttrKeyClass: `class`
        ]
        var error: Unmanaged<CFError>? = nil
        if let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) {
            return key
        } else if let error = error?.takeRetainedValue() {
            throw error
        } else {
            fatalError("should set error if key data is invalid")
        }
    }
    var attributes: [CFString: Any] {
        SecKeyCopyAttributes(self) as? [CFString: Any] ?? [:]
    }
    var isECKey: Bool {
        return self.isOfType(kSecAttrKeyTypeEC)
    }
    
    var isRSAKey: Bool {
        return self.isOfType(kSecAttrKeyTypeRSA)
    }
    private func isOfType(_ type: CFString) -> Bool {
        guard let keyType = self.attributes[kSecAttrKeyType] as? String else { return false }
        return keyType == type as String
    }
    
    var size: Int {
        guard let keySize = self.attributes[kSecAttrKeySizeInBits] as? Int else { return 0 }
        return keySize/8
    }
}

protocol SecKeySignature {
    var secKey: SecKey { get }
    var secKeyAlgorithm: SecKeyAlgorithm { get }
}
extension SecKeySignature {
    func verifySignature(input: Data, signature: Data) -> Bool {
        return SecKeyVerifySignature(self.secKey, self.secKeyAlgorithm, input as CFData, signature as CFData, nil)
    }
    func generateSignature(_ input: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        if let result = SecKeyCreateSignature(self.secKey, self.secKeyAlgorithm, input as CFData, &error) {
            return result as Data
        } else if let error = error?.takeRetainedValue() {
            throw error
        } else {
            fatalError("should set error if key data is invalid")
        }
    }
}

extension NSError {
    convenience init(osStatus: OSStatus) {
        self.init(domain: NSOSStatusErrorDomain, code: Int(osStatus), userInfo: nil)
    }
}

