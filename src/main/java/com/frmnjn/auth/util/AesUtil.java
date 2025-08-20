package com.frmnjn.auth.util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AesUtil {

  // Generate a new AES secret key (256-bit if JCE Unlimited Strength is enabled)
  public static SecretKey generateKey(int n) throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(n); // 128, 192 or 256 bits
    return keyGen.generateKey();
  }

  // Convert a SecretKey to string (Base64 encoded)
  public static String keyToString(SecretKey secretKey) {
    return Base64.getEncoder().encodeToString(secretKey.getEncoded());
  }

  // Convert a Base64 encoded string back to SecretKey
  public static SecretKey stringToKey(String encodedKey) {
    byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
    return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
  }

  // Encrypt text using AES key
  public static String encrypt(String plainText, SecretKey secretKey) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF-8"));
    return Base64.getEncoder().encodeToString(cipherText);
  }

  // Decrypt text using AES key
  public static String decrypt(String cipherText, SecretKey secretKey) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
    return new String(plainText, "UTF-8");
  }

  // Example usage
  public static void main(String[] args) throws Exception {
    // Generate AES Key
    SecretKey key = generateKey(128); // or 256
    String keyString = keyToString(key);
    System.out.println("Generated Key: " + keyString);

    // Encrypt
    String original = "Hello Secure World!";
    String encrypted = encrypt(original, key);
    System.out.println("Encrypted: " + encrypted);

    // Decrypt
    String decrypted = decrypt(encrypted, key);
    System.out.println("Decrypted: " + decrypted);
  }
}
