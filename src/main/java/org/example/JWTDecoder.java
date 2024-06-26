package org.example;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.json.JSONObject;

import java.text.ParseException;
import java.util.Base64;
import java.util.Map;
import java.util.Scanner;

public class JWTDecoder {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Ask for JWT string
        System.out.println("Enter the JWT string:");
        String jwtString = scanner.nextLine();

        // Ask for the shared secret key
        System.out.println("Enter the shared secret key:");
        String sharedSecret = scanner.nextLine();

        try {
            // Parse the JWT
            SignedJWT signedJWT = SignedJWT.parse(jwtString);

            // Verify the JWT
            JWSVerifier verifier = new MACVerifier(sharedSecret.getBytes());
            boolean isVerified = signedJWT.verify(verifier);

            // Display the JWT header
            JWSHeader header = signedJWT.getHeader();
            System.out.println("JWT Header:");
            System.out.println(header.toJSONObject());

            // Display the JWT payload
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Map<String, Object> claims = claimsSet.getClaims();

            System.out.println("JWT Payload (Decoded):");
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                String claimName = entry.getKey();
                String encodedClaimValue = entry.getValue().toString();
                String decodedClaimValue = new String(Base64.getUrlDecoder().decode(encodedClaimValue));
                System.out.println(claimName + ": " + decodedClaimValue);
            }

            // Display the JWT signature verification status
            System.out.println("Signature Verification Status: " + (isVerified ? "VALID" : "INVALID"));

        } catch (ParseException | JOSEException e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
