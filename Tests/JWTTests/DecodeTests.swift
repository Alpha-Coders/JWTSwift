//
//  DecodeTests.swift
//
//  Created by Antoine Palazzolo on 24/12/20.
//

import Foundation

@testable import JWTSwift
import XCTest

class DecodeTests : XCTestCase {
    func testInvalidStructure() throws {
        let rawJWT = try ["invalid_structure","invalid_structure_2"].map(ReadRawSampleWithName)
        try rawJWT.forEach {
            do {
                _ = try JWTStandard(string: $0)
                XCTFail("should fail")
            } catch JWTStandard.DecodingError.invalidTokenStructure {
                // ok
            } catch {
                throw error
            }
        }
    }
    func testInvalidBase64() throws {
        let invalidHeaderRawJWT = try ReadRawSampleWithName("invalid_header_base64")
        do {
            _ = try JWTStandard(string: invalidHeaderRawJWT)
            XCTFail("should fail")
        } catch JWTStandard.DecodingError.invalidBase64URLEncoding { /* ok */ } catch {
            throw error
        }
        
        let invalidPayloadRawJWT = try ReadRawSampleWithName("invalid_payload_base64")
        do {
            _ = try JWTStandard(string: invalidPayloadRawJWT)
            XCTFail("should fail")
        } catch JWTStandard.DecodingError.invalidBase64URLEncoding { /* ok */ } catch {
            throw error
        }
        
        let invalidSignatureRawJWT = try ReadRawSampleWithName("invalid_signature_base64")
        do {
            _ = try JWTStandard(string: invalidSignatureRawJWT)
            XCTFail("should fail")
        } catch JWTStandard.DecodingError.invalidBase64URLEncoding { /* ok */ } catch {
            throw error
        }
    }
    func testInvalidJSON() throws {
        let invalidHeaderRawJWT = try ReadRawSampleWithName("invalid_header_json")
        do {
            _ = try JWTStandard(string: invalidHeaderRawJWT)
            XCTFail("should fail")
        } catch DecodingError.dataCorrupted { /* ok */ } catch {
            throw error
        }
        
        let invalidPayloadRawJWT = try ReadRawSampleWithName("invalid_payload_json")
        do {
            _ = try JWTStandard(string: invalidPayloadRawJWT)
            XCTFail("should fail")
        } catch DecodingError.dataCorrupted { /* ok */ } catch {
            throw error
        }
    }
    
    func testHeaderContent() throws {
        let missingAlgRawJWT = try ReadRawSampleWithName("invalid_missing_alg")
        do {
            _ = try JWTStandard(string: missingAlgRawJWT)
            XCTFail("should fail")
        } catch DecodingError.keyNotFound(JWTStandard.Header.CodingKeys.algorithm, _) { /* ok */ } catch {
            throw error
        }
        
        let invalidAlgRawJWT = try ReadRawSampleWithName("invalid_alg")
        _ = try JWTStandard(string: invalidAlgRawJWT) // should not fail
        
        let missingTyp = try ReadRawSampleWithName("valid_missing_typ")
        _ = try JWTStandard(string: missingTyp) // should not fail
    }
    
    func testValidateAllClaims() throws {
        _ = try ["all_claim_valid_1","all_claim_valid_2"].map(ReadSampleWithName)
    }
    func testValidateAllClaimsSigned() throws {
        let jwt = try ReadSampleWithName("all_claim_valid_2_signed")
        let verifier = HMACSignature(hashFunction: .sha256, secret: "secret")
        XCTAssertTrue(jwt.validateSignature(verifier))
    }
    
    func testValidateClaimsGetter() throws {
        _ = try ["all_claim_valid_1","all_claim_valid_2"].map(ReadSampleWithName)
    }
    func testValidateClaimsEmpty() throws {
        _ = try ["empty","empty2"].map(ReadSampleWithName)
    }
    func testInvalidAudience() {
        do {
            _ = try ReadSampleWithName("invalid_aud_format")
            XCTFail("should fail")
        } catch { /* ok */ }
    }
    func testInvalidExp() throws {
        do {
            _ = try ReadSampleWithName("invalid_exp_format")
            XCTFail("should fail")
        } catch { /* ok */ }
        
        _ = try ReadSampleWithName("invalid_expired") // should not fail
    }
    func testInvalidIat() {
        do {
            _ = try ReadSampleWithName("invalid_iat_format")
            XCTFail("should fail")
        } catch { /* ok */ }
    }
    func testInvalidIss() {
        do {
            _ = try ReadSampleWithName("invalid_iss_format")
            XCTFail("should fail")
        } catch { /* ok */ }
    }
    func testInvalidJWTIdentifier() {
        do {
            _ = try ReadSampleWithName("invalid_jti_format")
            XCTFail("should fail")
        } catch { /* ok */ }
    }
    func testInvalidNbf() throws {
        do {
            _ = try ReadSampleWithName("invalid_nbf_format")
            XCTFail("should fail")
        } catch { /* ok */ }
        
        _ = try ReadSampleWithName("invalid_nbf_immature")
    }
    func testInvalidSub() throws {
        do {
            _ = try ReadSampleWithName("invalid_sub_format")
            XCTFail("should fail")
        } catch { /* ok */ }
    }
}
