/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.toto.keytool;

import java.security.KeyPair;

/**
 *
 * @author Thanapongn
 */
public class App {

    public static void main(String args[]) throws Exception {
        KeyPair pair = SecureMessage.getKeyPairFromKeyStore();

        //Our secret message
        String message = "secret message";

        //Encrypt the message
        String cipherText = SecureMessage.encrypt(message, pair.getPublic());
        
        System.out.println("encrypt sender message : "+ cipherText);

        //Now decrypt it
        String decipheredMessage = SecureMessage.decrypt(cipherText, pair.getPrivate());
        
        System.out.println("decrypt message : "+ decipheredMessage);

        //sign our message
        String signature = SecureMessage.sign("toto", pair.getPrivate());

        System.out.println("signature : "+ signature);
        
        //check the signature
        boolean isCorrect = SecureMessage.verify("toto", signature, pair.getPublic());
        System.out.println("Signature correct: " + isCorrect);
    }

}
