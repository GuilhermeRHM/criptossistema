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
            // cria uma instancia de Cifra utilizando o algoritmo AES
            cifra = Cipher.getInstance(ALGORITMO_SIMETRICO);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] criptografar(String texto, byte[] bytesDeChave)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {
        // cria uma chave secreta utilizando os bytes da chave secreta utilizando o algoritmo AES
        SecretKey chaveSecreta = new SecretKeySpec(bytesDeChave, ALGORITMO_SIMETRICO);

        // inicializa a Cifra para criptografar utilizando a chave secreta
        cifra.init(Cipher.ENCRYPT_MODE, chaveSecreta);

        // retorna o texto criptografado
        return cifra.doFinal(texto.getBytes(StandardCharsets.UTF_8));
    }

    public static String descriptografar(
            byte[] bytes,
            byte[] bytesDeChave
    )
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {
        // cria uma chave secreta utilizando os bytes da chave secreta utilizando o algoritmo AES
        SecretKey chaveSecreta = new SecretKeySpec(bytesDeChave, ALGORITMO_SIMETRICO);

        // inicializa a Cifra para descriptografar utilizando a chave secreta
        cifra.init(Cipher.DECRYPT_MODE, chaveSecreta);

        // retorna o texto descriptografado
        return new String(cifra.doFinal(bytes), StandardCharsets.UTF_8);
    }
}
