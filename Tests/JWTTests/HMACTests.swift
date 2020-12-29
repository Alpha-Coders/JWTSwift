//
//  HMACTests.swift
//
//  Created by Antoine Palazzolo on 23/12/20.
//

import XCTest
import JWTSwift

class HMACTests : XCTestCase {
    
    func testHS256VerifySuccess() throws {
        try self.assertSampleSuccess(name: "HS256", hashFunction: .sha256, secret: "secret")
    }
    func testHS256VerifyFailure() throws {
        try self.assertSampleFailure(name: "HS256", hashFunction: .sha256, secret: "secretr")
        try self.assertSampleFailure(name: "HS256", hashFunction: .sha512, secret: "secret")
    }
    func testHS384VerifySuccess() throws {
        try self.assertSampleSuccess(name: "HS384", hashFunction: .sha384, secret: "secret")
    }
    func testHS384VerifyFailure() throws {
        try self.assertSampleFailure(name: "HS384", hashFunction: .sha384, secret: "secretr")
        try self.assertSampleFailure(name: "HS384", hashFunction: .sha256, secret: "secret")
    }
    func testHS512VerifySuccess() throws {
        try self.assertSampleSuccess(name: "HS512", hashFunction: .sha512, secret: "secret")
    }
    func testHS512VerifyFailure() throws {
        try self.assertSampleFailure(name: "HS512", hashFunction: .sha512, secret: "secretr")
        try self.assertSampleFailure(name: "HS512", hashFunction: .sha256, secret: "secret")
    }
    func testFailureWithOtherAlg() throws {
        try self.assertSampleFailure(name: "RS256", hashFunction: .sha256, secret: "secret")
    }
    func assertSampleFailure(name: String, hashFunction: HashFunction, secret: String,
                             file: StaticString = #filePath, line: UInt = #line) throws {
        let jwt = try ReadSampleWithName(name)
        let result = jwt.validateSignature(HMACSignature(hashFunction: hashFunction, secret: secret))
        XCTAssertFalse(result, file: file, line: line)
    }
    func assertSampleSuccess(name: String, hashFunction: HashFunction, secret: String,
                             file: StaticString = #filePath, line: UInt = #line) throws {
        let jwt = try ReadSampleWithName(name)
        let result = jwt.validateSignature(HMACSignature(hashFunction: hashFunction, secret: secret))
        XCTAssertTrue(result, file: file, line: line)
    }
    
    func testHS256Sign() throws {
        let signer = HMACSignature(hashFunction: .sha256, secret: "secret")
        let jwt = try JWT(payload: SamplePayload, signer: signer)
        let verifier = signer
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
    func testHS384Sign() throws {
        let signer = HMACSignature(hashFunction: .sha384, secret: "secret")
        let jwt = try JWT(payload: SamplePayload, signer: signer)
        let verifier = signer
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
    func testHS512Sign() throws {
        let signer = HMACSignature(hashFunction: .sha512, secret: "secret")
        let jwt = try JWT(payload: SamplePayload, signer: signer)
        let verifier = signer
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
}
