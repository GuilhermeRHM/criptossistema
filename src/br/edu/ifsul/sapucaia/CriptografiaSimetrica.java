package br.edu.ifsul.sapucaia;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class CriptografiaSimetrica {
    private static final String ALGORITMO_SIMETRICO = "AES";
    private static Cipher cifra;

    static {
        try {
            cifra = Cipher.getInstance(ALGORITMO_SIMETRICO);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] criptografar(byte[] bytes, byte[] bytesDeChave)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {
        SecretKey chaveSecreta = new SecretKeySpec(bytesDeChave, ALGORITMO_SIMETRICO);

        cifra.init(Cipher.ENCRYPT_MODE, chaveSecreta);

        return cifra.doFinal(bytes);
    }

    public static byte[] descriptografar(
            byte[] bytes,
            byte[] bytesDeChave
    )
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {
        SecretKey chaveSecreta = new SecretKeySpec(bytesDeChave, ALGORITMO_SIMETRICO);

        cifra.init(Cipher.DECRYPT_MODE, chaveSecreta);

        return cifra.doFinal(bytes);
    }
}
