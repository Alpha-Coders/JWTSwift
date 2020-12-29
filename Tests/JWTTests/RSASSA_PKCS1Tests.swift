//
//  RSASSA_PKCS1Tests.swift
//
//  Created by Antoine Palazzolo on 23/12/20.
//

import XCTest
import JWTSwift

class RSASSA_PKCS1Tests: XCTestCase {
    
    func testRS256VerifySuccess() throws {
        try self.assertSampleSuccess(name: "RS256", hashFunction: .sha256, key: RSA1_PublicKey)
    }
    func testRS256VerifyFailure() throws {
        try self.assertSampleFailure(name: "RS256", hashFunction: .sha256, key: RSA2_PublicKey)
        try self.assertSampleFailure(name: "RS256", hashFunction: .sha384, key: RSA1_PublicKey)
    }
    func testRS384VerifySuccess() throws {
        try self.assertSampleSuccess(name: "RS384", hashFunction: .sha384, key: RSA1_PublicKey)
    }
    func testRS384VerifyFailure() throws {
        try self.assertSampleFailure(name: "RS384", hashFunction: .sha384, key: RSA2_PublicKey)
        try self.assertSampleFailure(name: "RS384", hashFunction: .sha256, key: RSA1_PublicKey)
    }
    func testRS512VerifySuccess() throws {
        try self.assertSampleSuccess(name: "RS512", hashFunction: .sha512, key: RSA1_PublicKey)
    }
    func testRS512VerifyFailure() throws {
        try self.assertSampleFailure(name: "RS512", hashFunction: .sha512, key: RSA2_PublicKey)
        try self.assertSampleFailure(name: "RS512", hashFunction: .sha256, key: RSA1_PublicKey)
    }
    func testFailureWithOtherAlg() throws {
        try self.assertSampleFailure(name: "HS256", hashFunction: .sha256, key: RSA1_PublicKey)
    }
    
    func assertSampleFailure(name: String, hashFunction: HashFunction, key: RSAKey.Public,
                             file: StaticString = #filePath, line: UInt = #line) throws {
        let jwt = try ReadSampleWithName(name)
        let verifier = RSASSA_PKCS1Verifier(hashFunction: hashFunction, publicKey: key)
        let result = jwt.validateSignature(verifier)
        XCTAssertFalse(result, file: file, line: line)
    }
    func assertSampleSuccess(name: String, hashFunction: HashFunction, key: RSAKey.Public,
                             file: StaticString = #filePath, line: UInt = #line) throws {
        let jwt = try ReadSampleWithName(name)
        let verifier = RSASSA_PKCS1Verifier(hashFunction: hashFunction, publicKey: key)
        let result = jwt.validateSignature(verifier)
        XCTAssertTrue(result, file: file, line: line)
    }
    
    func testRS256Sign() throws {
        let signer = RSASSA_PKCS1Signer(hashFunction: .sha256, privateKey: RSA1_PrivateKey)
        let jwt = try JWT(payload: SamplePayload, signer: signer)
        let verifier = RSASSA_PKCS1Verifier(hashFunction: .sha256, publicKey: RSA1_PublicKey)
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
    func testRS384Sign() throws {
        let signer = RSASSA_PKCS1Signer(hashFunction: .sha384, privateKey: RSA1_PrivateKey)
        let jwt = try JWT(payload: SamplePayload, signer: signer)
        let verifier = RSASSA_PKCS1Verifier(hashFunction: .sha384, publicKey: RSA1_PublicKey)
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
    func testRS512Sign() throws {
        let signer = RSASSA_PKCS1Signer(hashFunction: .sha512, privateKey: RSA1_PrivateKey)
        let jwt = try JWT(payload: SamplePayload, signer: signer)
        let verifier = RSASSA_PKCS1Verifier(hashFunction: .sha512, publicKey: RSA1_PublicKey)
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
    func testCertificateImport() throws {
        let certificateData = try Data(contentsOf: testDataURL(name: "rsa1_public", extension: "cer"))
        _ = try RSAKey.Public(certificateData: certificateData)
    }
    func testCertificateImportInvalidData() throws {
        do {
            _ = try RSAKey.Public(certificateData: Data("this_is_not_a_certificate".utf8))
            XCTFail("should fail")
        } catch { /* ok */ }
        
        do {
            let data = try! Data(contentsOf: testDataURL(name: "ec1_public", extension: "cer"))
            _ = try RSAKey.Public(certificateData: data)
            XCTFail("should fail")
        } catch { /* ok */ }
    }
    
    func testBadKeyFormatAndPassword() throws {
        do {
            _ = try RSAKey.Public(pkcs1Key: Data("this_is_not_a_rsa_key".utf8))
            XCTFail("should fail")
        } catch { /* ok */ }
        
        do {
            _ = try RSAKey.keysFromPKCS12Identity(EC2_IdentityData, passphrase: "1234")
            XCTFail("should fail")
        } catch { /* ok */ }
        
        do {
            _ = try RSAKey.keysFromPKCS12Identity(RSA1_IdentityData, passphrase: "wrongpassword")
            XCTFail("should fail")
        } catch { /* ok */ }
    }
    
}
