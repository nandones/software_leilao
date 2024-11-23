/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.certificateauthority;

import java.util.HashMap;

/**
 *
 * @author nandones
 */
public class CAregisters {
     
    /**
     * <cpf : publicKeyBase64>
     */
    public static HashMap<String, String> certificates = new HashMap<>();

    /**
     * so, in a real implementation the values in the mock inside the constructor would been serialized and just desserialized on this method, but as a evaluation of computational security, thats fine.
     */
    public CAregisters() {
        certificates.put("00000000001","MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwQE2546Kw5F80HCSWAQnjeL03RNzTWMzkVa4ttQU0VBMu88Eq1hBmyOWOjDtckq3RA5lcoE+LCgw5vUV5FKG934TIrFYORCWujflZ7qpkmCDjb0+ePcWQKS8/pPbQtw/2GWJ7HdqH9C0GK5abGM8OJc+kCQ6W8HCts1if/2UrnKI2+L4yrmOo1dpAWoLlzbmXtxFyRxxruTTgTQ7y5KSWVGwOzlqrOzZvP0YjFyzjIfsyVz/IOP5F7IZfK6dja/I1A4Old4qsGslIfmMHesHduXbCM5ZC1bJHqDLtpUkcjSr/A9M0iJQbWv7hA6g/0Q24XUN4B+NtFAs1ki5NhPGjQIDAQAB");
        certificates.put("00000000002","MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu54fYijPozPW7sDGLgFwQZ8d12edkxl4MBaFRMMgwuQ/m0kDjueg+czWiZtRHb3TJV6LnVxhJSg2p2W7EMODO7a/A223EBgZI2UkN+BKGpvvNHu/bf/XO+rOWzafKLdt5+8OY59xHRrmDri4AaunKaPNggNbXtg4tF1IO0Bz2fv7kQF3niSF3bkImNU9RE8HgU25nXrJe6N+Vtli26lMzw3LrckRu2Ue9JSeaCXJtTqISHcsC4fRa8EN9rKbCx9yphkfmGg6VlLqvk0r1KCwCkWGnG3AC1p4b1flvjgCGTlW9KgZB8ccOXsG/5WXirxqJMAirD/RdsF+IkHmI5W4qwIDAQAB");
        certificates.put("00000000003","MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp3NsyW3wFF66x2SuHf/YxHlFfeX1HzxyFwmBDDarxAGq0VxwLJdRv/mBeaM9k4Nru2wMCCUiWAIGmh183AYwMJU7HQTe0/aw/7AEwRxTBq8clzvRrx5RfHiPvc8pqeghDy0jx6Gl3Ky7+9NPipcwW8mVJRpYIDlQeFRi7eZvx772XpMjs0+mC0pnSJWm8ReqWi4aQFs4zjVz3E8xuWk+mGZSoo1ZsOUhP98zROl3A53GqCw/8qq0lnM7j4UlHbPiRwkRuAPx4Z591qDengKepmY5Suq7wfObZgyHlxxe+pFO45a5w1C63AzKWJh2KCUI6Zad8N0LKhHFw3URj054CQIDAQAB");
    }
    
    /**
     * 
     * @param CPF
     * @return the public key of this CPF as base64. If there is no corresponding key, returns null.
     */
    public String returnPublicKeyBase64(String CPF){
        if(certificates.containsKey(CPF)){
            return certificates.get(CPF);
        }
        return null;
        
    }
    
    
    
}
