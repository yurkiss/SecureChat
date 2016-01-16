/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ua.softserve.chat.security;

import javax.crypto.*;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author yrid
 */
public class EncodedReader {

    private final InputStream in;
    private final String mCipherAlgorythm;
    private final SecretKey mSharedSecretKey;

    public EncodedReader(InputStream in, String cipherAlgorythm, SecretKey sharedSecretKey) {
        this.in = in;
        this.mCipherAlgorythm = cipherAlgorythm;
        this.mSharedSecretKey = sharedSecretKey;
    }

    public String read() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        
        int length = in.read();
        if(length > 0){
            byte[] b = new byte[length];
            int res = in.read(b, 0, length);
            if(res == -1){
            }else if(res != length){
                System.out.println("res != length " + res + " != " + length);
            }         
            
            //decode
            Cipher cipher = Cipher.getInstance(mCipherAlgorythm);
            cipher.init(Cipher.DECRYPT_MODE, mSharedSecretKey);
            byte[] decodedBytes = cipher.doFinal(b);
            
            return new String(decodedBytes, "UTF-8");
        }        
        
        return null;
    }
    

}
