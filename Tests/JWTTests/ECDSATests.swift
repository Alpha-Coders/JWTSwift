//
//  ECDSATests.swift
//
//  Created by Antoine Palazzolo on 24/12/20.
//

import JWTSwift
import XCTest

class ECDSATests : XCTestCase {
    
    func testES256VerifySuccess() throws {
        try self.assertSampleSuccess(name: "ES256", hashFunction: .sha256, key: EC1_PublicKey)
    }
    func testES256VerifyFailure() throws {
        try self.assertSampleFailure(name: "ES256", hashFunction: .sha256, key: EC2_PublicKey)
        try self.assertSampleFailure(name: "ES256", hashFunction: .sha384, key: EC1_PublicKey)
    }
    func testES384VerifySuccess() throws {
        try self.assertSampleSuccess(name: "ES384", hashFunction: .sha384, key: EC1_PublicKey)
    }
    func testES384VerifyFailure() throws {
        try self.assertSampleFailure(name: "ES384", hashFunction: .sha384, key: EC2_PublicKey)
        try self.assertSampleFailure(name: "ES384", hashFunction: .sha256, key: EC1_PublicKey)
    }
    func testES512VerifySuccess() throws {
        try self.assertSampleSuccess(name: "ES512", hashFunction: .sha512, key: EC1_PublicKey)
    }
    func testES512VerifyFailure() throws {
        try self.assertSampleFailure(name: "ES512", hashFunction: .sha512, key: EC2_PublicKey)
        try self.assertSampleFailure(name: "ES512", hashFunction: .sha256, key: EC1_PublicKey)
    }
    func testFailureWithOtherAlg() throws {
        try self.assertSampleFailure(name: "RS256", hashFunction: .sha256, key: EC1_PublicKey)
    }
    
    func assertSampleFailure(name: String, hashFunction: HashFunction, key: ECKey.Public,
                             file: StaticString = #filePath, line: UInt = #line) throws {
        let jwt = try ReadSampleWithName(name)
        let verifier = ECDSAVerifier(hashFunction: hashFunction, publicKey: key)
        let result = jwt.validateSignature(verifier)
        XCTAssertFalse(result, file: file, line: line)
    }
    func assertSampleSuccess(name: String, hashFunction: HashFunction, key: ECKey.Public,
                             file: StaticString = #filePath, line: UInt = #line) throws {
        let jwt = try ReadSampleWithName(name)
        let verifier = ECDSAVerifier(hashFunction: hashFunction, publicKey: key)
        let result = jwt.validateSignature(verifier)
        XCTAssertTrue(result, file: file, line: line)
    }
    
    func testES256Sign() throws {
        let signer = ECDSASigner(hashFunction: .sha256, privateKey: EC1_PrivateKey)
        let jwt = try JWT(payload: SamplePayload, signer: signer)
        let verifier = ECDSAVerifier(hashFunction: .sha256, publicKey: EC1_PublicKey)
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
    func testES384Sign() throws {
        let signer = ECDSASigner(hashFunction: .sha384, privateKey: EC1_PrivateKey)
        let jwt = try JWT(payload: SamplePayload, signer: signer)
        let verifier = ECDSAVerifier(hashFunction: .sha384, publicKey: EC1_PublicKey)
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
    func testES512Sign() throws {
        let signer = ECDSASigner(hashFunction: .sha512, privateKey: EC1_PrivateKey)
        let jwt = try JWT(payload: SamplePayload, signer: signer)
        let verifier = ECDSAVerifier(hashFunction: .sha512, publicKey: EC1_PublicKey)
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
    
    func testCertificateImport() throws {
        let certificateData = try Data(contentsOf: testDataURL(name: "ec1_public", extension: "cer"))
        _ = try ECKey.Public(certificateData: certificateData)
    }
    func testCertificateImportInvalidData() throws {
        do {
            _ = try ECKey.Public(certificateData: Data("this_is_not_a_certificate".utf8))
            XCTFail("should fail")
        } catch { /* ok */ }
        
        do {
            let data = try! Data(contentsOf: testDataURL(name: "rsa1_public", extension: "cer"))
            _ = try ECKey.Public(certificateData: data)
            XCTFail("should fail")
        } catch { /* ok */ }
    }
    
    func testBadKeyFormatAndPassword() throws {
        do {
            _ = try ECKey.Public(x963Key: Data("this_is_not_a_rsa_key".utf8))
            XCTFail("should fail")
        } catch { /* ok */ }
        
        do {
            _ = try ECKey.keysFromPKCS12Identity(RSA1_IdentityData, passphrase: "1234")
            XCTFail("should fail")
        } catch { /* ok */ }
        
        do {
            _ = try ECKey.keysFromPKCS12Identity(EC2_IdentityData, passphrase: "wrongpassword")
            XCTFail("should fail")
        } catch { /* ok */ }
    }
}
