package com.tacigar.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public final class TryJavaJwt {

    private static final String secret = "12b8dc92fa99bc";
    private static final String issuer = "MyIdP";
    private static final String subject = "1abc93cdf20c";

    public static void main(String[] args) {
        final String token;

        try {
            final Algorithm algorithm = Algorithm.HMAC256(secret);
            token = JWT.create()
                       .withSubject(subject)
                       .withIssuer(issuer)
                       .withClaim("name", "Tacigar")
                       .sign(algorithm);
            System.out.printf("generated token: %s\n", token);
        } catch (JWTCreationException exception){
            System.out.printf("failed to generate a jwt token: %s\n", exception.getMessage());
            System.exit(1);
            return;
        }

        try {
            final Algorithm algorithm = Algorithm.HMAC256(secret);
            final JWTVerifier verifier = JWT.require(algorithm)
                                            .withIssuer(issuer)
                                            .build(); //Reusable verifier instance
            final DecodedJWT jwt = verifier.verify(token);
            System.out.printf("subject: %s\n", jwt.getClaim("sub").asString());
            System.out.printf("issuer: %s\n", jwt.getClaim("iss").asString());
            System.out.printf("name: %s\n", jwt.getClaim("name").asString());
        } catch (JWTVerificationException exception){
            System.out.printf("failed to verify the token: %s\n", exception.getMessage());
            System.exit(1);
        }
    }
}
