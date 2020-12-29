//
//  Data+Base64URLEncoding.swift
//
//
//  Created by Antoine Palazzolo on 22/12/2020.
//

import Foundation

extension Data {
    init?(base64URLEncoded input: String, options: Data.Base64DecodingOptions = []) {
        var input = input
        input = input.replacingOccurrences(of: "-", with: "+")
        input = input.replacingOccurrences(of: "_", with: "/")

        let padding = Array(repeating: "=", count: input.count % 4).joined()
        input.append(padding)
        
        if let decoded = Data(base64Encoded: input, options: options) {
             self = decoded
        } else {
            return nil
        }
    }
    func base64URLEncodedString(options: Data.Base64EncodingOptions = []) -> String {
        var output = self.base64EncodedString(options: options)
        output = output.replacingOccurrences(of: "+", with: "-")
        output = output.replacingOccurrences(of: "/", with: "_")
        output = output.replacingOccurrences(of: "=", with: "")
        return output
    }
}
