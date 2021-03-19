package br.edu.ifsul.sapucaia;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class GeradorDeChaveSecreta {
    private static final String SECRET_KEY_FACTORY_ALGORITMO = "PBKDF2WithHmacSHA256";
    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] gerarSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        return salt;
    }

    public static byte[] gerarChaveSecreta(String senha)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_ALGORITMO);

        KeySpec especificacoesDaChave = new PBEKeySpec(
                senha.toCharArray(),
                gerarSalt(),
                100000,
                256
        );

        SecretKey chaveSecreta = secretKeyFactory.generateSecret(especificacoesDaChave);

        return chaveSecreta.getEncoded();
    }
}
