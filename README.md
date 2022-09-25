# dFido2Lib-ios
A FIDO2 native framework for iOS.  
FIDO2/WebAuthn heavily depends on browsers' implementation. A native lib is significantly usable in providing stable and customizable user experiences.

## Target of this project
1. a Modern project 

  * Modern Swift async/await mechanism rather than embedded callbacks. 
  * Support the latest FIDO spec

2. Use OS native lib as many as possible

3. Keep the external APIs as simple as possible and speak the programers' language

4. Keep source code structure as simple as possible

## Core APIs
* registerAuthenticator
* authenticate

## Util APIs
* Fido2Util.getDefaultRegisterOptions
* Fido2Core.reset
* Fido2Core.clearKeys
* Fido2Core.configExcaptionTimeoutWaiting
* Fido2Core.configMultipleCredByMultipleTransports
* Fido2Core.configInsideAuthenticatorResidentStorage
* Fido2Core.enabledInsideAuthenticatorResidentStorage
* Fido2Core.configInsideAuthenticatorSilentCredentialDiscovery
* Fido2Core.configeInsideAuthenticatorDfaultServicePrefix


## Compatible FIDO2 servers 
* fido2-node (https://github.com/dqj1998/fido2-node.git) 

* LINE FIDO2 server (https://github.com/line/line-fido2-server.git).  
(Does not support real non-resident credentials)

## Thanks
* https://github.com/lyokato/WebAuthnKit-iOS.git

## Contact
* d@dqj.work
