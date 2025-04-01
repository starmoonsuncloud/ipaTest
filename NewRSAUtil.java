package com.aia.iengage.util;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Slf4j
public class NewRSAUtil {

    private static final String xml = "<?xml version='1.0' encoding='ISO-8859-1'?><GUSession><GU_SessionID>0e2532e2ee4dd3f23696bc6c7ebdbac609747c9af006a5c0acd630087aadd111</GU_SessionID><GU_AppID>IENG</GU_AppID><GU_UserID>78932</GU_UserID><GU_UserType>AGENT</GU_UserType></GUSession>";

    private static final String R_A_S = "RSA";
    private static final String RAS_PAD = "RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING";

    private static final int MAX_ENCRYPT_BLOCK = 214;
    private static final int MAX_DECRYPT_BLOCK = 256;

    public static void main(String[] args) {
        String encrypt = null;
        String decrypt = null;
        try {
            encrypt = encrypt(xml, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApJOznYlkhC2x4eeC0SvRtv9wUAor+1O/x2I3M5RV9fybxVCnpiDF9XPJP9vsWfYW2RIyFczXKiKH5PTNoFAxb4tPfPzacdsFXQSmX1Rf3jRBHN8e/WWwdyslQzoE/9G9OMRD+4iQ5eYnpBF+XXuXZ6D4BEIN31Ix/VOErpn0BUwJadtZcc4r6qcloci86SGxv+iYKjJB8dk8M6s56IcVGvagR3QWIpiPXxy1f6900IypWllbUc+FJDo8gxQcJTqyW5rj5TZrMBBiNplxFtRJbEfeAUTkjn/aIZ/jZ57fkqW4tMtEf+sL+k+VlPzQIhefz1cvnMah+HWg2sPRtMxxgQIDAQAB");
            decrypt = decrypt(encrypt, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkk7OdiWSELbHh54LRK9G2/3BQCiv7U7/HYjczlFX1/JvFUKemIMX1c8k/2+xZ9hbZEjIVzNcqIofk9M2gUDFvi098/Npx2wVdBKZfVF/eNEEc3x79ZbB3KyVDOgT/0b04xEP7iJDl5iekEX5de5dnoPgEQg3fUjH9U4SumfQFTAlp21lxzivqpyWhyLzpIbG/6JgqMkHx2TwzqznohxUa9qBHdBYimI9fHLV/r3TQjKlaWVtRz4UkOjyDFBwlOrJbmuPlNmswEGI2mXEW1ElsR94BROSOf9ohn+Nnnt+Spbi0y0R/6wv6T5WU/NAiF5/PVy+cxqH4daDaw9G0zHGBAgMBAAECggEABszjmxrWQG/y7ba3PRVmcP1VErmY36WyQvbX+RWkB6oMdbbDdqXcCCxkoHLh7UWx4/5Qe34fVepfWyKSbJFjuYw0GKIKFLJMIm/SwBWocHIQTrUZfrb497Ocso5vLnLoMrRJatdVxWohMTJX2l0FAI8yMFraX+PxlNoinWRXJPDSbAjiD63tOUSBC1aTUKb6jszkprm446hjoIW02VsY5l0Ttly9s6WI3siwWvJ/8lK3ds314By2TKBFGm0DjRNZi1uqTmEKbtLKMjcqXKQZhGHKLS/c01NkdaeEJ7WVwCcRiRsZe0a52P2LG6bE+1MwknUlNnHy7YB5zVKkSFhgkQKBgQDPLGbKKWIz9sG3LTwlRZCoLE2XNDEM6tNz3odveVsAR6PVHywS3SN1eUupsEihgc+axSWdvumytOR0unsB0f7AtCI2Tt1leVixhsyMsZhKFdJoeIxS50CHGyOEKUKHvrEwL6abZxkuamYu+BTp07LBBlM7U4ZU5wjC7WpueFlUgwKBgQDLXUjgJsS+7g+QgK+CKHRfn8IA/zva5mG85vmwDZ4Q5+8lleYRmpxg9SxCS+rmg83nfZ9yINVVhcfQmqSjZFq0I8PFN38jOK6EukJwUzqosspMaeYiLdgc2j7xR0WESLkBgg7crWii+jnvYt+FTf/qutyosnP57e/EzMmLCVaqqwKBgFpWMSgb7X9dLNET/3L9J3u9fcPd9Tl9t+CBeysHjr/LfUv0QMKk/M4/qtd+T91k/kKtjp5/XeYX7Lpdij+b8urSYUyvDOkvhZY7gjwjQJWleE8nqYCI5+FB2zXIzALnCtpJHOwMg7VyncYDVRM0xXBXsrlezWd+Kprc7ZjoD4PDAoGAcDmMa9Y5ILwy7qV1NTip79MztmUjXMtiCGLWS2dYYS/88xrjmbdesMrbn8JRYOA/ko3qnYqs78Mh32ZXkKtiuqI5+O2FRaST+j7nRyFG762qobyW+SmfZ1yw+2k/XZ7cKY7iMLmpUrcPnaFMhD3lCl4QQzAnfDbn6Ayy8/01TH0CgYEAgWJU+x5tv5flFmC+wPcYnXTW2q90N3sKUjKAFwiT/tmErGRGlOhRiw5fwUUYs1G9Z8Jt6hLOTuPxgKP4IJarm9BKyYyrmCNuKqVrN7j+/RPAfexNvVTy1Nr4d3J4qrAABSubtLSKtLYk76Tyoylz6lu34uGHmXV5XzLRyv+ZJGw=");
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("xml:" + xml);
        System.out.println("Encrypt:" + encrypt);
        System.out.println("Decrypt:" + decrypt);
        System.out.println("Test:" + xml.equals(decrypt));
    }

    public static String encrypt(String str, String publicKey) throws Exception {
        byte[] decoded = org.apache.commons.codec.binary.Base64.decodeBase64(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance(R_A_S).generatePublic(new X509EncodedKeySpec(decoded));
        Cipher cipher = Cipher.getInstance(RAS_PAD);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);

        byte[] bytes = str.getBytes(StandardCharsets.UTF_8.name());

        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            int length = bytes.length;

            int offSet = 0;
            byte[] cache;
            int i = 0;
            while (length - offSet > 0) {
                if (length - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(bytes, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(bytes, offSet, length - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] encryptedData = out.toByteArray();
            return org.apache.commons.codec.binary.Base64.encodeBase64String(encryptedData);
        }
    }

    public static String decrypt(String str, String privateKey) throws Exception {
        byte[] inputByte = org.apache.commons.codec.binary.Base64.decodeBase64(str.getBytes(StandardCharsets.UTF_8.name()));
        byte[] decoded = org.apache.commons.codec.binary.Base64.decodeBase64(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance(R_A_S).generatePrivate(new PKCS8EncodedKeySpec(decoded));
        Cipher cipher = Cipher.getInstance(RAS_PAD);
        cipher.init(Cipher.DECRYPT_MODE, priKey);

        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            int length = inputByte.length;
            int offSet = 0;
            byte[] cache;
            int i = 0;
            while (length - offSet > 0) {
                if (length - offSet > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(inputByte, offSet, MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(inputByte, offSet, length - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_DECRYPT_BLOCK;
            }
            return out.toString();
        }
    }

}
