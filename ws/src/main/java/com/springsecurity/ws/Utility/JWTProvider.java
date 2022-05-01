package com.springsecurity.ws.Utility;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.springsecurity.ws.Entity.UserData;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

@Component
public class JWTProvider {

        @Value("${jwt.SSS}")
    private String JWTsecret;

    public String generateJwtToken(UserData userPrincipal) {
        String sssToken;
        String[] claims = getClaimsFromUser(userPrincipal);
        Algorithm algorithm = Algorithm.HMAC512(JWTsecret.getBytes(StandardCharsets.UTF_8));
        System.out.println("secret="+ JWTsecret);
        try{
            sssToken=JWT.create()
                    .withIssuer("auth0")
                    .withIssuedAt(new Date())
                    .withSubject(userPrincipal.getUsername())
                    .withArrayClaim("AUTHORITIES SSS", claims)
                    .withExpiresAt(new Date(System.currentTimeMillis()+360000000))
                    .sign(algorithm);
        }




        catch (JWTCreationException exception){
            throw new JWTVerificationException(exception.getMessage());
        }
        System.out.println(sssToken);
        return sssToken;

    }

    public List<GrantedAuthority> getAuthorities(String token) {
        String[] claims = getClaimsFromToken(token);
        return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    public Authentication getAuthentication(String username, List<GrantedAuthority> authorities, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken userPasswordAuthToken = new
                UsernamePasswordAuthenticationToken(username, null, authorities);
        userPasswordAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return userPasswordAuthToken;
    }

    public boolean isTokenValid(String username, String token) {
        DecodedJWT verifier = getJWTVerifier(token);
        return StringUtils.isNotEmpty(username) && !isTokenExpired(verifier, token);
    }

    public String getSubject(String token) {
        DecodedJWT verifier = getJWTVerifier(token);
        return verifier.getSubject();
    }

    private boolean isTokenExpired(DecodedJWT verifier, String token) {
       // = verifier.verify(token).getExpiresAt();
        DecodedJWT verifiers = getJWTVerifier(token);
        Date expiration=verifiers.getExpiresAt();
        return expiration.before(new Date());
    }

    private String[] getClaimsFromToken(String token) {
        DecodedJWT verifier = getJWTVerifier(token);
        return verifier.getClaim("AUTHORITIES SSS").asArray(String.class);
    }

    private DecodedJWT getJWTVerifier(String token) {
        JWTVerifier verifier;
        DecodedJWT jwt;
        try {
            Algorithm algorithm = Algorithm.HMAC512(JWTsecret.getBytes(StandardCharsets.UTF_8));
            verifier = JWT.require(algorithm).withIssuer("auth0").build();
            jwt=verifier.verify(token);
            System.out.println("RAHU VERIFIER A BA ZIN");
        }catch (JWTVerificationException exception) {
            throw new JWTVerificationException(exception.getMessage());
        }
        return jwt;
    }

    private String[] getClaimsFromUser(UserData user) {
        List<String> authorities = new ArrayList<>();
        for (GrantedAuthority grantedAuthority : user.getAuthorities()){
            authorities.add(grantedAuthority.getAuthority());
        }
        return authorities.toArray(new String[0]);
    }
}
