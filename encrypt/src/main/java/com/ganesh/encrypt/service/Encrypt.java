package com.ganesh.encrypt.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class Encrypt {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding"; // AES with CBC mode and PKCS5 Padding
    private static final int SALT_LENGTH = 16;


    public static byte[] generateSalt() {
        SecureRandom sr = new SecureRandom();
        byte salt[] = new byte[SALT_LENGTH];
        sr.nextBytes(salt);
        return salt;
    }

    public static SecretKey deriveKey() throws Exception {
        KeyGenerator key = KeyGenerator.getInstance(ALGORITHM);
        key.init(128);
        SecretKey secretKey = key.generateKey();
        return secretKey;
    }

    public static String encrypt(String text, SecretKey secretKey, byte[] salt)
            throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(), new IvParameterSpec(generateSalt()));
        byte[] encrypted = cipher.doFinal(text.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);

    }


    public static String decrypt(String cipherText, SecretKey secretKey, byte[] salt) {
        try {
            // Validate Base64 input
            byte[] decodedBytes = Base64.getDecoder().decode(cipherText);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, deriveKey(), new IvParameterSpec(salt));
            byte[] decrypted = cipher.doFinal(decodedBytes);
            return new String(decrypted);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Input is not a valid Base64-encoded string", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }


}
