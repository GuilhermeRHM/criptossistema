package br.edu.ifsul.sapucaia;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class CriptografiaAssimetrica {
    private static final String ALGORITMO_ASSIMETRICO = "RSA";
    private static final int TAMANHO_DA_CHAVE_RSA = 4096;
    private static KeyPairGenerator geradorDeParDeChaves;
    private static KeyPair parDeChaves;
    private static PrivateKey chavePrivada;
    private static PublicKey chavePublica;
    private static Cipher cifra;

    public static KeyPair gerarParDeChaves()
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        cifra = Cipher.getInstance(ALGORITMO_ASSIMETRICO);
        geradorDeParDeChaves = KeyPairGenerator.getInstance(ALGORITMO_ASSIMETRICO);
        geradorDeParDeChaves.initialize(TAMANHO_DA_CHAVE_RSA);

        parDeChaves = geradorDeParDeChaves.generateKeyPair();
        chavePrivada = parDeChaves.getPrivate();
        chavePublica = parDeChaves.getPublic();

        return parDeChaves;
    }

    public static byte[] criptografar(String texto, PrivateKey chavePrivada)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            UnsupportedEncodingException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException {
        // inicializa o objeto de cifra para criptografar passando a chave privada
        cifra.init(Cipher.ENCRYPT_MODE, chavePrivada);

        // retorna o array de byte do texto criptografado
        return cifra.doFinal(texto.getBytes(StandardCharsets.UTF_8));
    }

    public static String descriptografar(byte[] bytes, PublicKey chavePublica)
            throws InvalidKeyException, UnsupportedEncodingException,
            IllegalBlockSizeException, BadPaddingException {
        // inicializa o objeto de cifra para descriptografar passando a chave publica
        cifra.init(Cipher.DECRYPT_MODE, chavePublica);

        // retorna a String do texto descriptografado
        return new String(cifra.doFinal(bytes), StandardCharsets.UTF_8);
    }
}
