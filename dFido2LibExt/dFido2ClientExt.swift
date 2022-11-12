//
//  Fido2ExAPIs.swift
//  dFido2LibExt
//
//  Created by Du Qingjie on 2022/08/14.
//

import Foundation
import dFido2LibCore

//TODO: syncServerCredentails
// return: userhandles?
public class dFido2ClientExt{
    public static func syncServerCredentails(fido2SvrURL:String, rpId: String) -> Array<String> {
        var userhandles = Array<String>()
        
        return userhandles
    }
    
    public static func listAccounts(rpId: String) -> Optional<Accounts> {
        let accountsData = try? KeyTools.retrieveKey(keyChainId: Fido2Core.AccountsKeyId, handle: rpId)
        if nil != accountsData {
            let accounts = Accounts.fromJSON(json: String(data: accountsData!, encoding: .utf8)!)
            return accounts
        }
        return nil
    }
}
