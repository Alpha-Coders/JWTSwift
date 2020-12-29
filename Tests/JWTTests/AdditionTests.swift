//
//  AdditionTests.swift
//  
//
//  Created by Antoine Palazzolo on 29/12/2020.
//

import JWTSwift
import XCTest

class AdditionTests: XCTestCase {

    func testEquatableHashableStandard() throws {
        var payload1 = JWTStandard.Payload()
        payload1.tokenIdentifier = "24735AD1-FA89-48F3-B907-0C34B3C3725D"
        let jwt1 = try JWTStandard(payload: payload1)
        XCTAssertEqual(jwt1, try JWTStandard(payload: payload1))
        XCTAssertEqual(jwt1.hashValue, try JWTStandard(payload: payload1).hashValue)

        var payload2 = payload1
        payload2.tokenIdentifier = "CE38AA8D-0ADE-4A58-AF58-FC3EF1D415C8"
        let jwt2 = try JWTStandard(payload: payload2)
        XCTAssertNotEqual(jwt1, jwt2)

        let signer1 = HMACSignature(hashFunction: .sha256, secret: "secret1")
        let jwt3 = try JWTStandard(payload: payload1, signer: signer1)
        XCTAssertEqual(jwt3, try JWTStandard(payload: payload1, signer: signer1))
        XCTAssertEqual(jwt3.hashValue, try JWTStandard(payload: payload1, signer: signer1).hashValue)

        let signer2 = HMACSignature(hashFunction: .sha256, secret: "secret2")
        let jwt4 = try JWTStandard(payload: payload1, signer: signer2)
        XCTAssertNotEqual(jwt3, jwt4)

        var header1 = JWTStandard.Header(algorithm: .none)
        header1.contentType = "contentType1"
        let jwt5 = try JWTStandard(header: header1, payload: payload1)
        XCTAssertEqual(jwt5, try JWTStandard(header: header1, payload: payload1))
        XCTAssertEqual(jwt5.hashValue, try JWTStandard(header: header1, payload: payload1).hashValue)

        var header2 = header1
        header2.contentType = "contentType2"
        let jwt6 = try JWTStandard(header: header2, payload: payload1)
        XCTAssertNotEqual(jwt5, jwt6)
    }
    func testEquatableCustom() throws {
        struct CustomPayload: CustomPayloadClaims {
            var claim: String
        }
        struct CustomHeader: CustomHeaderFields {
            var field: String
        }
        typealias MyJWT = JWTCustom<CustomHeader, CustomPayload>
        
        let payload1 = MyJWT.Payload(customClaims: .init(claim: "claim1"))
        let header1 = MyJWT.Header(algorithm: .none, customFields: .init(field: "header1"))

        let jwt1 = try MyJWT(header: header1, payload: payload1)
        XCTAssertEqual(jwt1, try MyJWT(header: header1, payload: payload1))
        XCTAssertEqual(jwt1.hashValue, try MyJWT(header: header1, payload: payload1).hashValue)

        var payload2 = payload1
        payload2.claim = "claim2"
        let jwt2 = try MyJWT(header: header1, payload: payload2)
        XCTAssertNotEqual(jwt1, jwt2)
        
        let signer1 = HMACSignature(hashFunction: .sha256, secret: "secret1")
        let header1WithAlg =  MyJWT.Header(algorithm: signer1.algorithm, customFields: .init(field: "header1"))
        let jwt3 = try MyJWT(header: header1WithAlg, payload: payload1, signer: signer1)
        XCTAssertEqual(jwt3, try MyJWT(header: header1WithAlg, payload: payload1, signer: signer1))
        XCTAssertEqual(jwt3.hashValue, try MyJWT(header: header1WithAlg, payload: payload1, signer: signer1).hashValue)

        let signer2 = HMACSignature(hashFunction: .sha256, secret: "secret2")
        let jwt4 = try MyJWT(header: header1WithAlg, payload: payload1, signer: signer2)
        XCTAssertNotEqual(jwt3, jwt4)
        
        var header2 = header1
        header2.field = "field2"
        let jwt5 = try MyJWT(header: header2, payload: payload1)
        XCTAssertEqual(jwt5, try MyJWT(header: header2, payload: payload1))
              
        XCTAssertNotEqual(jwt1, jwt5)
    }
}
