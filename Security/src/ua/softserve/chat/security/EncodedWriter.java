/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ua.softserve.chat.security;

import javax.crypto.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author yrid
 */
public class EncodedWriter {

    private ByteArrayOutputStream buf;
    private final String mCipherAlgorythm;
    private final SecretKey mSharedSecretKey;

    public EncodedWriter(String cipherAlgorythm, SecretKey sharedSecretKey) {
        this.buf = new ByteArrayOutputStream();
        this.mCipherAlgorythm = cipherAlgorythm;
        this.mSharedSecretKey = sharedSecretKey;

    }

    public void writeLine(String line) throws IOException {
        byte[] b = line.getBytes("UTF-8");
        buf.write(b, 0, b.length);
    }

    private ByteArrayOutputStream encode() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(mCipherAlgorythm);
        cipher.init(Cipher.ENCRYPT_MODE, mSharedSecretKey);
        byte[] b = cipher.doFinal(buf.toByteArray());
        final ByteArrayOutputStream encodedBuf = new ByteArrayOutputStream(b.length);
        encodedBuf.write(b, 0, b.length);
        return encodedBuf;
    }

    public void sendTo(OutputStream out) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
        //Encode and send data
        ByteArrayOutputStream encByteArray = encode();
        out.write(encByteArray.size());
        encByteArray.writeTo(out);
        out.flush();
        buf.reset();

    }

}
