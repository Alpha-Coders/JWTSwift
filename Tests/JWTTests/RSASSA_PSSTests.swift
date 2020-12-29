//
//  RSASSA_PSSTests.swift
//
//  Created by Antoine Palazzolo on 24/12/20.
//

import Foundation
import JWTSwift
import XCTest

class RSASSA_PSSTests : XCTestCase {
    
    func testPS256VerifySuccess() throws {
        try self.assertSampleSuccess(name: "PS256", hashFunction: .sha256, key: RSA1_PublicKey)
    }
    func testPS256VerifyFailure() throws {
        try self.assertSampleFailure(name: "PS256", hashFunction: .sha256, key: RSA2_PublicKey)
        try self.assertSampleFailure(name: "PS256", hashFunction: .sha384, key: RSA1_PublicKey)
    }
    func testPS384VerifySuccess() throws {
        try self.assertSampleSuccess(name: "PS384", hashFunction: .sha384, key: RSA1_PublicKey)
    }
    func testPS384VerifyFailure() throws {
        try self.assertSampleFailure(name: "PS384", hashFunction: .sha384, key: RSA2_PublicKey)
        try self.assertSampleFailure(name: "PS384", hashFunction: .sha256, key: RSA1_PublicKey)
    }
    func testPS512VerifySuccess() throws {
        try self.assertSampleSuccess(name: "PS512", hashFunction: .sha512, key: RSA1_PublicKey)
    }
    func testPS512VerifyFailure() throws {
        try self.assertSampleFailure(name: "PS512", hashFunction: .sha512, key: RSA2_PublicKey)
        try self.assertSampleFailure(name: "PS512", hashFunction: .sha256, key: RSA1_PublicKey)
    }
    func testFailureWithOtherAlg() throws {
        try self.assertSampleFailure(name: "RS256", hashFunction: .sha256, key: RSA1_PublicKey)
    }
    
    func assertSampleFailure(name: String, hashFunction: HashFunction, key: RSAKey.Public,
                             file: StaticString = #filePath, line: UInt = #line) throws {
        let jwt = try ReadSampleWithName(name)
        let verifier = RSASSA_PSSVerifier(hashFunction: hashFunction, publicKey: key)
        let result = jwt.validateSignature(verifier)
        XCTAssertFalse(result, file: file, line: line)
    }
    func assertSampleSuccess(name: String, hashFunction: HashFunction, key: RSAKey.Public,
                             file: StaticString = #filePath, line: UInt = #line) throws {
        let jwt = try ReadSampleWithName(name)
        let verifier = RSASSA_PSSVerifier(hashFunction: hashFunction, publicKey: key)
        let result = jwt.validateSignature(verifier)
        XCTAssertTrue(result, file: file, line: line)
    }
    
    func testPS256Sign() throws {
        let signer = RSASSA_PSSSigner(hashFunction: .sha256, privateKey: RSA1_PrivateKey)
        let jwt = try JWT(payload: SamplePayload, signer: signer)
        let verifier = RSASSA_PSSVerifier(hashFunction: .sha256, publicKey: RSA1_PublicKey)
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
    func testPS384Sign() throws {
        let signer = RSASSA_PSSSigner(hashFunction: .sha384, privateKey: RSA1_PrivateKey)
        let jwt = try JWT(payload: SamplePayload, signer: signer)
        let verifier = RSASSA_PSSVerifier(hashFunction: .sha384, publicKey: RSA1_PublicKey)
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
    func testPS512Sign() throws {
        let signer = RSASSA_PSSSigner(hashFunction: .sha512, privateKey: RSA1_PrivateKey)
        let jwt = try JWT(payload: SamplePayload, signer: signer)
        let verifier = RSASSA_PSSVerifier(hashFunction: .sha512, publicKey: RSA1_PublicKey)
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
}
