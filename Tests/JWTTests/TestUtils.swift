//
//  TestUtils.swift
//
//  Created by Antoine Palazzolo on 23/12/20.
//

import Foundation
import JWTSwift

func testDataURL(name: String, extension: String) -> URL {
    let directory = URL(fileURLWithPath: #file).deletingLastPathComponent().appendingPathComponent("Samples")
    return directory.appendingPathComponent("\(name).\(`extension`)")
}
func ReadRawSampleWithName(_ name: String) throws -> String {
    let url = testDataURL(name: name, extension: "jwt")
    return try String(contentsOf: url, encoding: .utf8)
}
func ReadSampleWithName(_ name: String) throws -> JWTStandard {
    return try JWTStandard(string: ReadRawSampleWithName(name))
}

let RSA1_IdentityData = try! Data(contentsOf: testDataURL(name: "rsa1_identity", extension: "p12"))
let RSA1_Identity: (publicKey: RSAKey.Public, privateKey: RSAKey.Private) = {
    let p12Data = RSA1_IdentityData
    return try! RSAKey.keysFromPKCS12Identity(p12Data, passphrase: "1234")
}()
let RSA1_PublicKey: RSAKey.Public = { RSA1_Identity.publicKey }()
let RSA1_PrivateKey: RSAKey.Private = { RSA1_Identity.privateKey }()

let RSA2_IdentityData = try! Data(contentsOf: testDataURL(name: "rsa2_identity", extension: "p12"))
let RSA2_Identity: (publicKey: RSAKey.Public, privateKey: RSAKey.Private) = {
    let p12Data = RSA2_IdentityData
    return try! RSAKey.keysFromPKCS12Identity(p12Data, passphrase: "1234")
}()
let RSA2_PublicKey: RSAKey.Public = { RSA2_Identity.publicKey }()
let RSA2_PrivateKey: RSAKey.Private = { RSA2_Identity.privateKey }()

let EC1_IdentityData = try! Data(contentsOf: testDataURL(name: "ec1_identity", extension: "p12"))
let EC1_Identity: (publicKey: ECKey.Public, privateKey: ECKey.Private) = {
    return try! ECKey.keysFromPKCS12Identity(EC1_IdentityData, passphrase: "1234")
}()
let EC1_PublicKey: ECKey.Public = { EC1_Identity.publicKey }()
let EC1_PrivateKey: ECKey.Private = { EC1_Identity.privateKey }()

let EC2_IdentityData = try! Data(contentsOf: testDataURL(name: "ec2_identity", extension: "p12"))
let EC2_Identity: (publicKey: ECKey.Public, privateKey: ECKey.Private) = {
    return try! ECKey.keysFromPKCS12Identity(EC2_IdentityData, passphrase: "1234")
}()
let EC2_PublicKey: ECKey.Public = { EC2_Identity.publicKey }()
let EC2_PrivateKey: ECKey.Private = { EC2_Identity.privateKey }()

let SamplePayload: JWT<SampleCustomPayloadClaims>.Payload = {
    var payload = JWT<SampleCustomPayloadClaims>.Payload(customClaims: SampleCustomPayloadClaims())
    payload.issuer = "1234567890"
    payload.name = "John Doe"
    return payload
}()

struct SampleCustomPayloadClaims: CustomPayloadClaims {
    var name: String = ""
}
