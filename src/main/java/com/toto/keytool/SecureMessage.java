package com.toto.keytool;

import java.io.FileInputStream;
import java.io.InputStream;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import javax.crypto.Cipher;

/**
 *
 * @author Thanapongn <Toto>
 */
public class SecureMessage {

    //TODO: read it from configure
    private static final String PASSWORD = "123456789";
    private static final String ALIAS = "toto2c2p";
    private static final String JSK_PATH = "D:\\Security\\2c2p_sha1.jks";

    public static KeyPair getKeyPairFromKeyStore() throws Exception {
        //Generated with:
        //  keytool -genkey -alias toto2c2p -keyalg RSA -sigalg SHA256withRSA -keysize 2048 -validity 3650 -keystore 2c2p.jks
        //  keytool -genkey -alias toto2c2p -keyalg RSA -sigalg SHA1withRSA -keysize 2048 -validity 3650 -keystore 2c2p.jks

        InputStream ins = new FileInputStream(JSK_PATH);
        char[] passwordArray = PASSWORD.toCharArray();
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, passwordArray);  
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(passwordArray);

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS, keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate(ALIAS);
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }
    
    public static java.security.cert.Certificate getCertificate() throws Exception {
        //Generated with:
        //  keytool -genkey -alias toto2c2p -keyalg RSA -sigalg SHA256withRSA -keysize 2048 -validity 3650 -keystore 2c2p.jks

        InputStream ins = new FileInputStream(JSK_PATH);
        char[] passwordArray = PASSWORD.toCharArray();
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, passwordArray);  
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(passwordArray);

        java.security.cert.Certificate cert = keyStore.getCertificate(ALIAS);

        return cert;
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

}
