package com.example.algorithm.encrypt;

import com.example.algorithm.AlgorithmApplicationTests;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * @Description：
 * @Auther： libo
 * @date： 2018/9/12:22:10
 */
@Slf4j
@Component
public class AesCBCTest extends AlgorithmApplicationTests {

    private final String key = "test-key";
    private final String iv = "test-iv";
    private final String encodingFormat = "UTF-8";

    @Test
    public void encrypt() throws Exception {
        Map<String, String> map = new HashMap<>();
        map.put("name", "Gzhennaxia");
        Gson gson = new Gson();
        String dataString = gson.toJson(map);
        String encryptedString = AesCBC.encrypt(dataString, key, iv, encodingFormat);
        log.info("encryptedString={}", encryptedString);
        // key=dGVzdC1rZXkwMDAwMDAwMA==
        // iv=dGVzdC1pdjAwMDAwMDAwMA==
        // encryptedString=LXKs4XhHqMitYTLa5nxGs27V2wB81P6UuSKWUbsyvr8=
    }

    @Test
    public void decrypt() throws Exception {
        String key = "dGVzdC1rZXkwMDAwMDAwMA==";
        String iv = "dGVzdC1pdjAwMDAwMDAwMA==";
        String encryptedString = "LXKs4XhHqMitYTLa5nxGs27V2wB81P6UuSKWUbsyvr8=";
        String decryptedString = AesCBC.decrypt(encryptedString, key, iv, encodingFormat);
        log.info("decryptedString={}",decryptedString);
        // decryptedString={"name":"Gzhennaxia"}
    }
}