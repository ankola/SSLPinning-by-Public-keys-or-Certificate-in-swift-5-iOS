//
//  ViewController.swift
//  SSLPinningDemo
//
//  Created by Savan on 21/07/23.
//

import UIKit
import Foundation
import Alamofire
import CryptoKit
import CommonCrypto

class ViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        wsHandler().apiCall()
        print("Bundle public keys: \(Bundle.main.af.publicKeys)")
    }
}

class wsHandler : SessionDelegate {
    var af2 = Session.default
    
    //get publicKeyHash
    //openssl s_client -servername www.boredapi.com -connect www.boredapi.com:443 | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64

    static let publicKeyHash = "iD3PVt4S0h8tzAJfsAKEmwq4m3Y3PLKwOWO6Ea9UsHg="
    
    init() {
        super.init()
        self.af2 = Session.init(configuration: URLSessionConfiguration.ephemeral, delegate: self)
    }
    
    override func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        if let trust = challenge.protectionSpace.serverTrust, let serverCertificate = SecTrustGetCertificateAtIndex(trust, 0) {
            // Server public key
            let serverPublicKey = SecCertificateCopyKey(serverCertificate)
            let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil )!
            let data:Data = serverPublicKeyData as Data
            // Server Hash key
            let serverHashKey = sha256(data: data)
            // Local Hash Key
            let publickKeyLocal = type(of: self).publicKeyHash
            if (serverHashKey == publickKeyLocal) {
                // Success! This is our server
                print("Public key pinning is successfully completed")
                completionHandler(.useCredential, URLCredential(trust:trust))
                return
            } else {
                print("Access denied, failed to connect with secure connection.")
            }
        }
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
    
    private func sha256(data: Data) -> String {
        let rsa2048Asn1Header: [UInt8] = [
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
        ]
        
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        
        if #available(iOS 13.0, *) {
            let hash = SHA256.hash(data: keyWithHeader)
            let hashData = Data(hash)
            return hashData.base64EncodedString()
        } else {
            // Fallback on earlier versions
            var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            keyWithHeader.withUnsafeBytes { dataBytes in
                _ = CC_SHA256(dataBytes.baseAddress, CC_LONG(keyWithHeader.count), &hash)
            }
            let hashData = Data(hash)
            return hashData.base64EncodedString()
        }
    }
    
    func apiCall() {
        self.af2.request(URL(string: "https://www.boredapi.com/api/activity")!, method: .get, parameters: nil, encoding: JSONEncoding.default, headers: nil,requestModifier: { (request) in
            request.timeoutInterval = 120
        }).responseJSON { (response) in
            switch (response.result) {
            case .success(_):
                print("success")
                //self.successBlock(urlStr, response, block)
            case .failure(let error):
                print(error)
                //self.errorBlock(urlStr, error as NSError, block)
            }
        }
    }
}
