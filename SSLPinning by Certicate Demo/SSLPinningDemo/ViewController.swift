//
//  ViewController.swift
//  SSLPinningDemo
//
//  Created by Savan on 21/07/23.
//

//SSL Pinning by Certificate
//1. Add certificate to keychain
//2. Set always trust in keychain
//3. Export certificate from keychain
//4. Add certificate in project
//5. Check keys are added or not. print("Bundle public keys: \(Bundle.main.af.publicKeys)")
//
//6. private lazy var certificates: [Data] = {
//         let url = Bundle.main.url(forResource: "certificate_name", withExtension: "cer")
//         let data = try! Data(contentsOf: url!)
//         return [data]
//   }()
//
//7. var af2 = Session.default
//8. self.af2 = Session.init(configuration: URLSessionConfiguration.ephemeral, delegate: self)
//
//9. Add SessionDelegate
//
//10. Add SessionDelegate Method
//override func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
//    if let trust = challenge.protectionSpace.serverTrust, SecTrustGetCertificateCount(trust) > 0 {
//        if let certificate = SecTrustGetCertificateAtIndex(trust, 0) {
//            let data = SecCertificateCopyData(certificate) as Data
//            if certificates.contains(data) {
//                completionHandler(.useCredential, URLCredential(trust: trust))
//                return
//            } else {
//                print("Access denied, failed to connect with secure connection.")
//            }
//        }
//    }
//    completionHandler(.cancelAuthenticationChallenge, nil)
//}



import UIKit
import Alamofire

class ViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        wsHandler().apiCall()
    }
}

class wsHandler : SessionDelegate {
    var af2 = Session.default

    private lazy var certificates: [Data] = {
        let url = Bundle.main.url(forResource: "certificate_name", withExtension: "cer")!
        let data = try! Data(contentsOf: url)
        return [data]
    }()
    
    init() {
        super.init()
        self.af2 = Session.init(configuration: URLSessionConfiguration.ephemeral, delegate: self)
    }
    
    override func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
                
        if let trust = challenge.protectionSpace.serverTrust, SecTrustGetCertificateCount(trust) > 0 {
            if let certificate = SecTrustGetCertificateAtIndex(trust, 0) {
                let data = SecCertificateCopyData(certificate) as Data
                if certificates.contains(data) {
                    print("SSL pinning by certificate  is successfully completed")
                    completionHandler(.useCredential, URLCredential(trust: trust))
                    return
                } else {
                    print("Access denied, failed to connect with secure connection.")
                }
            }
        }
        completionHandler(.cancelAuthenticationChallenge, nil)
      }
    
    func apiCall() {
        self.af2.request(URL(string: "api")!, method: .post, parameters: nil, encoding: JSONEncoding.default, headers: nil,requestModifier: { (request) in
            request.timeoutInterval = 120
        }).responseJSON { (response) in
            switch (response.result) {
            case .success(_):
                print("success")
                //self.successBlock(urlStr, response, block)
            case .failure(let error):
                print(error.localizedDescription)
                //self.errorBlock(urlStr, error as NSError, block)
            }
        }
    }
}



