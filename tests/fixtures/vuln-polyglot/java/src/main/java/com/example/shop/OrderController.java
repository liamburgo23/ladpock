package com.example.shop;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*")
@RestController
public class OrderController {
    private Connection connection;

    @GetMapping("/orders")
    public ResultSet orders(@RequestParam String customer) throws Exception {
        return connection.createStatement().executeQuery("SELECT * FROM orders WHERE customer = '" + customer + "'");
    }

    String hashPassword(String password) throws Exception {
        return new String(MessageDigest.getInstance("MD5").digest(password.getBytes()));
    }

    byte[] encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        return cipher.doFinal(data);
    }

    Object parse(java.io.InputStream xml) throws Exception {
        return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xml);
    }
}
