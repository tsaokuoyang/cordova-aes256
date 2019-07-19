import CryptoSwift;
import CommonCrypto;

@objc(AES256) class AES256 : CDVPlugin {
    
    private static let SECURE_KEY_LENGTH = 16;
    private static let SECURE_IV_LENGTH = 8;
    private static let PBKDF2_ITERATION_COUNT = 1001;
    private static let aes256Queue = DispatchQueue(label: "AESQUEUE", qos: DispatchQoS.background, attributes: .concurrent)

    // Encrypts the plain text using aes256 encryption alogrithm
    @objc(encrypt:) func encrypt(_ command: CDVInvokedUrlCommand) {
        AES256.aes256Queue.async {
	        var pluginResult = CDVPluginResult(
	            status: CDVCommandStatus_ERROR,
	            messageAs: "Error occurred while performing Encryption"
	        )
	        
	        let secureKey = command.arguments[0] as? String ?? ""
	        let iv = command.arguments[1] as? String ?? ""
	        let value = command.arguments[2] as? String ?? ""
	        
	        
	        // let encrypted = AES256CBC.encryptString(value, password: secureKey, iv: iv)
        	let encrypted: String = value.aesEncrypt(key: secureKey, iv: iv)!
	        pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: encrypted)
	        
	        self.commandDelegate!.send(
	            pluginResult, 
	            callbackId: command.callbackId
	        )
		}
    }
    
    // Decrypts the aes256 encoded string into plain text
    @objc(decrypt:) func decrypt(_ command: CDVInvokedUrlCommand) {
        AES256.aes256Queue.async {
	        var pluginResult = CDVPluginResult(
	            status: CDVCommandStatus_ERROR,
	            messageAs: "Error occurred while performing Decryption"
	        )
	        
	        let secureKey = command.arguments[0] as? String ?? ""
	        let iv = command.arguments[1] as? String ?? ""
	        let value = command.arguments[2] as? String ?? ""

			// let decrypted = AES256CBC.decryptString(value, password: secureKey, iv: iv)
        	let decrypted: String = value.aesDecrypt(key: secureKey, iv: iv)!
	        pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: decrypted)
	        
	        self.commandDelegate!.send(
	            pluginResult,
	            callbackId: command.callbackId
	        )
		}
    }
    
    // Generates the secure key from the given password
    @objc(generateSecureKey:) func generateSecureKey(_ command: CDVInvokedUrlCommand) {
      	AES256.aes256Queue.async {
	        var pluginResult = CDVPluginResult(
	            status: CDVCommandStatus_ERROR,
	            messageAs: "Error occurred while generating secure key"
	        )
	        
	        let password = command.arguments[0] as? String ?? ""
	        let secureKey:String? = PBKDF2.pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password:password, salt:AES256CBC.generateSalt(), keyByteCount:AES256.SECURE_KEY_LENGTH, rounds:AES256.PBKDF2_ITERATION_COUNT)
	        
	        pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: secureKey)
	        
	        self.commandDelegate!.send(
	            pluginResult,
	            callbackId: command.callbackId
	        )
		}
    }
    
    // Generates the IV from the given password
    @objc(generateSecureIV:) func generateSecureIV(_ command: CDVInvokedUrlCommand) {
      	AES256.aes256Queue.async {
	        var pluginResult = CDVPluginResult(
	            status: CDVCommandStatus_ERROR,
	            messageAs: "Error occurred while generating secure IV"
	        )
	
	        let password = command.arguments[0] as? String ?? ""
	        let secureIV:String? = PBKDF2.pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password:password, salt:AES256CBC.generateSalt(), keyByteCount:AES256.SECURE_IV_LENGTH, rounds:AES256.PBKDF2_ITERATION_COUNT)
	        
	        pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: secureIV)
	        
	        self.commandDelegate!.send(
	            pluginResult,
	            callbackId: command.callbackId
	        )
		}
    }
}


extension String {
    
    /// AES加密
    ///
    /// - Parameters:
    ///   - key: key
    ///   - iv: iv
    /// - Returns: String
    func aesEncrypt(key: String, iv: String) -> String? {
        var result: String?
        do {
            // 用UTF8的编碼方式將字串轉成Data
            let data: Data = self.data(using: String.Encoding.utf8, allowLossyConversion: true)!
            
            // 用AES的方式將Data加密
            let aecEnc: AES = try AES(key: key, iv: iv, blockMode: .CBC)
            let enc = try aecEnc.encrypt(data.bytes)
            
            // 使用Base64編碼方式將Data轉回字串
            let encData: Data = Data(bytes: enc, count: enc.count)
            result = encData.base64EncodedString()
        } catch {
            print("\(error.localizedDescription)")
        }
        
        return result
    }
    
    /// AES解密
    ///
    /// - Parameters:
    ///   - key: key
    ///   - iv: iv
    /// - Returns: String
    func aesDecrypt(key: String, iv: String) -> String? {
        var result: String?
        do {
            // 使用Base64的解碼方式將字串解碼後再轉换Data
            let data = Data(base64Encoded: self, options: Data.Base64DecodingOptions(rawValue: 0))!
            
            // 用AES方式將Data解密
            let aesDec: AES = try AES(key: key, iv: iv, blockMode: .CBC)
            let dec = try aesDec.decrypt(data.bytes)
            
            // 用UTF8的編碼方式將解完密的Data轉回字串
            let desData: Data = Data(bytes: dec, count: dec.count)
            result = String(data: desData, encoding: .utf8)!
        } catch {
            print("\(error.localizedDescription)")
        }
        
        return result
    }
}
