package br.edu.ifsul.sapucaia;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class CriptografiaAssimetrica {
    private static final String ALGORITMO_ASSIMETRICO = "RSA";
    private static final int TAMANHO_DA_CHAVE_RSA = 4096;
    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static final Base64.Decoder DECODER = Base64.getDecoder();
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

    public static byte[] criptografar(byte[] bytes, PrivateKey chavePrivada)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            UnsupportedEncodingException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException {
        cifra.init(Cipher.ENCRYPT_MODE, chavePrivada);

        return ENCODER.encode(
                cifra.doFinal(bytes)
        );
    }

    public static byte[] descriptografar(byte[] bytes, PublicKey chavePublica)
            throws InvalidKeyException, UnsupportedEncodingException,
            IllegalBlockSizeException, BadPaddingException {
        cifra.init(Cipher.DECRYPT_MODE, chavePublica);

        return cifra.doFinal(DECODER.decode(bytes));
    }
}
