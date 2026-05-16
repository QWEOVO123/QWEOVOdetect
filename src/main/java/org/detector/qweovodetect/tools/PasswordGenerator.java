package org.detector.qweovodetect.tools;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//用于生成密码哈希值
public class PasswordGenerator {
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String hash = encoder.encode("password");//此处输入原始密码，运行后得到哈希值
        System.out.println("Encode Hash is: " + hash);
    }
}