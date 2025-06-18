package com.ganesh.encrypt.Controller;


import com.ganesh.encrypt.service.Encrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.util.Base64;

@CrossOrigin(origins = "http://localhost:3000")
@RestController
@RequestMapping("/api")
public class EncryptDecryptController {

    @Autowired
    private Encrypt encrypt;

    private SecretKey secretKey;
    private byte[] salt;

    public EncryptDecryptController() throws Exception {
        this.secretKey = Encrypt.deriveKey();
        this.salt = Encrypt.generateSalt();
    }

    @GetMapping("/")
    public String Sample() {
        return "Hello World";
    }

    @PostMapping("/encrypt")
    public String encryptString(@RequestBody String input) throws Exception {
        if (input == null || input.isEmpty()) {
            return "Input string is null or empty";
        }

        // Encrypt the input string using the pre-generated key and salt
        String encryptedString = Encrypt.encrypt(input, secretKey, salt);
        return Base64.getEncoder().encodeToString(encryptedString.getBytes());

    }

    @PostMapping("/decrypt")
    public String decryptString(@RequestBody String input) throws Exception {
        if (input == null || input.isEmpty()) {
            return "Input string is null or empty";
        }
        try {
            // Decode the Base64 string
            byte[] decodedBytes = Base64.getDecoder().decode(input);
            String decodedString = new String(decodedBytes);
            // Decrypt the decoded string using the pre-generated key and salt
            return Encrypt.decrypt(decodedString, secretKey, salt);
        } catch (IllegalArgumentException e) {
            return "Invalid Base64 input: " + input;
        }
    }


}

