package br.edu.ifsul.sapucaia;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.PBEKey;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;
import java.util.Scanner;

public class Main {
    private static final String PADRAO_DE_DATE_TIME = "dd/MM/uuuu - HH:mm:ss";
    private static final DateTimeFormatter FORMATADOR_DE_DATE_TIME = DateTimeFormatter
            .ofPattern(PADRAO_DE_DATE_TIME)
            .withResolverStyle(ResolverStyle.STRICT);
    private static Scanner scanner = new Scanner(System.in);

    private static String buscarDateTimeAtualFormatado() {
        return FORMATADOR_DE_DATE_TIME.format(LocalDateTime.now());
    }

    private static void output(String mensagem) {
        String formato = "[%s] %s";

        System.out.printf(
                formato,
                buscarDateTimeAtualFormatado(),
                mensagem
        );
    }

    private static String input(String mensagem) {
        output(mensagem);

        return scanner.nextLine();
    }

    private static PBEKey gerarChaveSecretaComSenha()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        // usuário digita a senha
        String senha = input("Digite sua senha: ");

        // gera a chave secreta baseada na senha
        PBEKey chaveSecreta = GeradorDeChaveSecreta.gerarChaveSecreta(senha);

        // converte array de bytes em String
        String hex = new BigInteger(1, chaveSecreta.getEncoded())
                .toString(16);

        // printa no console a chave secreta
        output("Chave secreta: " + hex);

        return chaveSecreta;
    }

    private static void cifragemEDecifragemComCriptografiaSimetrica(PBEKey chaveSecreta)
            throws IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        // usuario digita texto para ser criptografado
        String texto = input("Digite texto para criptografar: ");

        // criptografa o texto digitado
        byte[] textoCriptografado = CriptografiaSimetrica.criptografar(
                texto.getBytes(StandardCharsets.UTF_8),
                chaveSecreta.getEncoded()
        );

        // printa no console o texto criptografado
        output(
                String.format(
                        "Texto criptografado: %s\n",
                        new BigInteger(
                                1,
                                textoCriptografado
                        ).toString(16)
                )
        );

        // descriptografa o texto
        String textoDescriptografado = CriptografiaSimetrica.descriptografar(
                textoCriptografado,
                chaveSecreta.getEncoded()
        );

        // printa no console o texto descriptografado
        output(
                String.format(
                        "Texto descriptografado: %s\n",
                        textoDescriptografado
                )
        );
    }

    private static void cifragemEDecifragemComCriptografiaAssimetrica(String chaveSecreta)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, UnsupportedEncodingException {
        KeyPair parDeChaves = CriptografiaAssimetrica.gerarParDeChaves();

        byte[] chaveCriptografada = CriptografiaAssimetrica.criptografar(
                chaveSecreta,
                parDeChaves.getPrivate()
        );
        output(
                String.format(
                        "Chave criptografada: %s\n",
                        new BigInteger(
                                1,
                                chaveCriptografada
                        ).toString(16)
                )
        );

        String chaveDescriptografada = CriptografiaAssimetrica.descriptografar(
                chaveCriptografada,
                parDeChaves.getPublic()
        );
        output(
                String.format(
                        "Chave descriptografada: %s\n\n",
                        chaveDescriptografada
                )
        );
    }

    public static void main(String[] args)
            throws NoSuchAlgorithmException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchPaddingException,
            InvalidKeySpecException, UnsupportedEncodingException {
        System.out.println(
                "\n===================================================================================================\n" +
                        "Funcionalidade 1: Geração de uma chave secreta baseada em uma senha do usuário" +
                        "\n===================================================================================================\n"
        );
        // gera a chave secreta baseada na senha digitada
        PBEKey chaveSecreta = gerarChaveSecretaComSenha();

        System.out.println(
                "\n\n===================================================================================================\n" +
                        "Funcionalidade 2: Cifragem e decifragem de dados com criptografia simétrica usando a chave secreta" +
                        "\n===================================================================================================\n"
        );
        // cifra e decifra dados com a chave secreta
        cifragemEDecifragemComCriptografiaSimetrica(chaveSecreta);

        System.out.println(
                "\n===================================================================================================\n" +
                        "Funcionalidade 3: Cifragem e decifragem da chave através do uso de criptografia assimétrica" +
                        "\n===================================================================================================\n"
        );
        // converte a chave secreta para uma HexString e executa sua cifragem e decifragem
        cifragemEDecifragemComCriptografiaAssimetrica(
                new BigInteger(
                        1,
                        chaveSecreta.getEncoded()
                ).toString(16)
        );
    }
}
