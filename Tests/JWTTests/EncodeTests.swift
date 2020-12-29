//
//  EncodeTests.swift
//
//  Created by Antoine Palazzolo on 23/12/20.
//

@testable import JWTSwift
import XCTest

class EncodeTests : XCTestCase {
    
    func testGenerateWithNone() throws {
        let jwt = try JWT(payload: SamplePayload)
        XCTAssertEqual(jwt.header.algorithm, Algorithm.none)
        XCTAssertEqual(jwt.signature, Data())
    }
    func testGenerateStandard() throws {
        var header = JWTStandard.Header(algorithm: .none)
        header.tokenType = "JWT"
        header.contentType = "contenttype"
        header.keyIdentifier = "mykey"
        header.certificateChain = [Data("hello world".utf8)]
        header.certificateChainURL = URL(string: "https://alphacoders.io")!
        header.critical = ["iss", "sub"]
        
        var payload = JWTStandard.Payload()
        payload.issuer = "alphacoders.io"
        payload.subject = "antoine"
        payload.audience = ["coucou"]
        payload.expirationTime = Date(timeIntervalSinceReferenceDate: 100)
        payload.notBefore = Date(timeIntervalSinceReferenceDate: 50)
        payload.issuedAt = Date(timeIntervalSinceReferenceDate: 10)
        payload.tokenIdentifier = UUID().uuidString
        
        let jwt = try JWTStandard(header: header, payload: payload)
        let newJWT = try JWTStandard(string: jwt.rawValue)
        
        XCTAssertEqual(jwt.header.tokenType, newJWT.header.tokenType)
        XCTAssertEqual(jwt.header.contentType, newJWT.header.contentType)
        XCTAssertEqual(jwt.header.keyIdentifier, newJWT.header.keyIdentifier)
        XCTAssertEqual(jwt.header.certificateChain, newJWT.header.certificateChain)
        XCTAssertEqual(jwt.header.certificateChainURL, newJWT.header.certificateChainURL)
        XCTAssertEqual(jwt.header.critical, newJWT.header.critical)
        
        XCTAssertEqual(jwt.payload.issuer, newJWT.payload.issuer)
        XCTAssertEqual(jwt.payload.subject, newJWT.payload.subject)
        XCTAssertEqual(jwt.payload.audience, newJWT.payload.audience)
        XCTAssertEqual(jwt.payload.expirationTime, newJWT.payload.expirationTime)
        XCTAssertEqual(jwt.payload.notBefore, newJWT.payload.notBefore)
        XCTAssertEqual(jwt.payload.issuedAt, newJWT.payload.issuedAt)
        XCTAssertEqual(jwt.payload.tokenIdentifier, newJWT.payload.tokenIdentifier)
    }
    func testGenerateCustom() throws {
        struct CustomHeaderFields: JWTSwift.CustomHeaderFields {
            var contentEncoding: String = ""
        }
        struct CustomPayloadClaims: JWTSwift.CustomPayloadClaims {
            var name: String = ""
        }
        
        typealias JWTCustom = JWTSwift.JWTCustom<CustomHeaderFields, CustomPayloadClaims>
        
        var header = JWTCustom.Header(algorithm: .none, customFields: CustomHeaderFields())
        header.contentEncoding = "UTF8"
        var payload = JWTCustom.Payload(customClaims: CustomPayloadClaims())
        payload.name = "antoine"

        let jwt = try JWTCustom(header: header, payload: payload)
        let newJWT = try JWTCustom(string: jwt.rawValue)
        XCTAssertEqual(jwt.header.contentEncoding, newJWT.header.contentEncoding)
        XCTAssertEqual(jwt.payload.name, newJWT.payload.name)
    }
    
    func testCodable() throws {
        struct Container: Codable {
            var token: JWTStandard
        }
        var payload = JWTStandard.Payload()
        payload.tokenIdentifier = UUID().uuidString
        let jwt = try JWTStandard(payload: payload)
        
        let container = Container(token: jwt)
        
        let encoded = try JSONEncoder().encode(container)
        let jsonObject = try JSONSerialization.jsonObject(with: encoded, options: []) as! [String: String]
        XCTAssertEqual(jsonObject["token"], jwt.rawValue)
        
        let decoded = try JSONDecoder().decode(Container.self, from: encoded)
        XCTAssertEqual(decoded.token.payload.tokenIdentifier, payload.tokenIdentifier)
    }
    
    func testHeaderAlgorithmAndSignerMismatch() throws {
        do {
            _ = try JWTStandard(header: .init(algorithm: .hmac_256), payload: .init(), signer: nil)
            XCTFail("should fail")
        } catch JWTStandard.EncodingError.headerAndSignerAlgorithmMismatch { /* ok */ } catch {
            throw error
        }
        
    }
}
