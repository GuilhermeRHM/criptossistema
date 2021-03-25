package br.edu.ifsul.sapucaia;

import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class GeradorDeChaveSecreta {
    private static final String ALGORITMO_CRIPTOGRAFICO = "PBKDF2WithHmacSHA256";
    private static final SecureRandom RANDOM = new SecureRandom();

    // gera o salt utilizado para tornar única cada chave gerada — senhas iguais
    // não possuem chaves iguais
    private static byte[] gerarSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        return salt;
    }

    public static PBEKey gerarChaveSecreta(String senha)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        // inicializa uma instância da fábrica de chaves secretas utilizando o algoritmo PBKDF2
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ALGORITMO_CRIPTOGRAFICO);

        // cria o objeto de especificações da chave a ser gerada
        KeySpec especificacoesDaChave = new PBEKeySpec(
                senha.toCharArray(),
                gerarSalt(),
                100000,
                256
        );

        // cria a chave secreta do tipo PBE
        PBEKey chaveSecreta = (PBEKey) secretKeyFactory.generateSecret(especificacoesDaChave);

        // retorna a chave
        return chaveSecreta;
    }
}
