package com.example.shop;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "https://shop.example.com")
@RestController
public class OrderController {
    private Connection connection;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @GetMapping("/orders")
    public ResultSet orders(@RequestParam String customer) throws Exception {
        PreparedStatement statement = connection.prepareStatement("SELECT * FROM orders WHERE customer = ?");
        statement.setString(1, customer);
        return statement.executeQuery();
    }

    String hashPassword(String password) {
        return encoder.encode(password);
    }

    byte[] encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        return cipher.doFinal(data);
    }

    Object parse(java.io.InputStream xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newDocumentBuilder().parse(xml);
    }
}
