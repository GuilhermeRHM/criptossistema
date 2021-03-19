package br.edu.ifsul.sapucaia;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
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
        String formato = "\n[%s] %s";

        System.out.printf(
                formato,
                buscarDateTimeAtualFormatado(),
                mensagem
        );
    }

    private static String input() {
        return scanner.nextLine();
    }

    private static String input(String mensagem) {
        output(mensagem);

        return scanner.nextLine();
    }

    private static byte[] gerarChaveSecretaComSenha()
            throws InvalidKeySpecException, NoSuchAlgorithmException, UnsupportedEncodingException {
        String senha = input("Digite sua senha: ");

        byte[] chaveSecreta = GeradorDeChaveSecreta.gerarChaveSecreta(senha);

        output(
                String.format(
                        "Chave secreta: %s",
                        chaveSecreta
                )
        );

        return chaveSecreta;
    }

    private static void cifragemEDecifragemComCriptografiaSimetrica(byte[] chaveSecreta)
            throws IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException, UnsupportedEncodingException {
        String texto = input("Digite texto para criptografar: ");

        byte[] textoCriptografado = CriptografiaSimetrica.criptografar(
                texto.getBytes(StandardCharsets.UTF_8),
                chaveSecreta
        );
        output(
                String.format(
                        "Texto criptografado: %s\n",
                        textoCriptografado
                )
        );

        byte[] textoDescriptografado = CriptografiaSimetrica.descriptografar(
                textoCriptografado,
                chaveSecreta
        );
        output(
                String.format(
                        "Texto descriptografado: %s\n",
                        new String(textoDescriptografado, StandardCharsets.UTF_8)
                )
        );
    }

    private static void cifragemEDecifragemComCriptografiaAssimetrica(byte[] chaveSecreta)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, UnsupportedEncodingException {
        KeyPair parDeChaves = CriptografiaAssimetrica.gerarParDeChaves();

        byte[] chaveCriptografada = CriptografiaAssimetrica.criptografar(
                chaveSecreta.toString()
                        .getBytes(StandardCharsets.UTF_8),
                parDeChaves.getPrivate()
        );
        output(
                String.format(
                        "Chave criptografada: %s\n",
                        chaveCriptografada
                )
        );

        byte[] chaveDescriptografada = CriptografiaAssimetrica.descriptografar(
                chaveCriptografada,
                parDeChaves.getPublic()
        );
        output(
                String.format(
                        "Chave descriptografada: %s\n\n",
                        new String(chaveDescriptografada, StandardCharsets.UTF_8)
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
                "\n==================================================================================================="
        );
        byte[] chaveSecreta = gerarChaveSecretaComSenha();

        System.out.println(
                "\n\n===================================================================================================\n" +
                "Funcionalidade 2: Cifragem e decifragem de dados com criptografia simétrica usando a chave secreta" +
                "\n==================================================================================================="
        );
        cifragemEDecifragemComCriptografiaSimetrica(chaveSecreta);

        System.out.println(
                "\n===================================================================================================\n" +
                "Funcionalidade 3: Cifragem e decifragem da chave através do uso de criptografia assimétrica" +
                "\n==================================================================================================="
        );
        cifragemEDecifragemComCriptografiaAssimetrica(chaveSecreta);
    }
}
