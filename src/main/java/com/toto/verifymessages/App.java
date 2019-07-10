/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.toto.verifymessages;

import com.toto.keytool.SecureMessage;
import java.security.KeyPair;

/**
 *
 * @author Thanapongn
 */
public class App {

    public static void main(String args[]) throws Exception {
        KeyPair pair = SecureMessage.getKeyPairFromKeyStore();

        String signature = "IpJ9fKv6fj+Abbvuo8R4If/XwmLcjam49PVj/ecNToDV+a7zYrVZ//qXm7kfugkxknTNuTEzuLB25bn5R2RGKeDaUxnBS0HaTOgeFSgWcMBELq4229uOYAf3C+UyHreZSIcWDegA3+nE6pOkJSWjblUuPj6zwRJ52IDraOuiFayckiW6cqVmSl+mDgN2luXPAjY4jUFV1bgvbKGJDXZV9eYY9fSuhquRRKOci2/B6/odSd7h+qrxxgE6m4EwRqt0mZIlPyPzVhYbeGIvgBliXg/bIIE5nJ3BeAR6JE7bUO2AjPGQZsrvfzmvxgWHgt8nEyDGmMoJZ9tBrC5R7ucAig==";
        String plainText = "toto";
        //check the signature
        boolean isCorrect = SecureMessage.verify(plainText, signature, pair.getPublic());
        System.out.println("Signature correct: " + isCorrect);
    }
}
