package com.helloworldweb.gateway_service.Auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider {


    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final long accessTokenValidateSeconds = 1000L * 60 * 60 * 10;
    private final long refreshTokenValidateSeconds = 1000L * 60 * 60 * 24 * 14;

    private Key key;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String secret) {
        this.secret = secret;
    }

    @PostConstruct
    public void init() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }


    public String createToken(String userId) {
        Claims claims = Jwts.claims().setSubject(userId);

        long now = (new Date()).getTime();
        Date validTime = new Date(now + this.accessTokenValidateSeconds);

        return Jwts.builder()
                .setClaims(claims) // 데이터
                .setIssuedAt(new Date(now))   // 토큰 발행 일자
                .setExpiration(validTime) // 만료 기간
                .signWith(key, SignatureAlgorithm.HS256) // 암호화 알고리즘, secret 값
                .compact(); // Token 생성
    }

    public boolean validateTokenWithDate(String token) {
        try {
            Claims claims = Jwts
                    .parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    private String getUserIdFromJwt(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

}
