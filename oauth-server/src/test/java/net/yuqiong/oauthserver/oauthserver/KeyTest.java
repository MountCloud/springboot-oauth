package net.yuqiong.oauthserver.oauthserver;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;

import org.junit.jupiter.api.Test;

/**
 * TODO:
 *
 * @Author: MountCloud
 * @Date: 2024年07月09日
 */
public class KeyTest {

    @Test
    public void createKey(){
        try {
            // 创建一个 KeyPairGenerator 对象，并初始化为 RSA 算法
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // 可以设置密钥大小，例如 2048

            // 生成密钥对
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 保存公钥到文件
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
            Files.write(Paths.get("public.key"), x509EncodedKeySpec.getEncoded());

            // 保存私钥到文件
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
            Files.write(Paths.get("private.key"), pkcs8EncodedKeySpec.getEncoded());

            System.out.println("公钥和私钥已生成并保存到文件中");

        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    public void getKey(){

    }
}
