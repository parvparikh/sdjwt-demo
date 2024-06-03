package junk;

import com.authlete.sd.SDJWT;
import com.authlete.sd.Disclosure;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.List;
import java.util.Scanner;

public class SDJWT_demoVerify {

    private static final String SHARED_SECRET = "17627FB44D699A8A29E871FA8EFC8ABCDE0123456789ABCDEF0123456789AB";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter the SD-JWT:");
        String jwtString = scanner.nextLine();

        try {
            // Decode the SD-JWT
            SDJWT sdJwt = SDJWT.parse(jwtString);
            decodeSDJWT(sdJwt);
        } catch (JOSEException | ParseException e) {
            System.err.println("Error occurred while decoding SD-JWT: " + e.getMessage());
        }
    }

    private static void decodeSDJWT(SDJWT sdJwt) throws ParseException, JOSEException {
        // Extract JWT from SD-JWT
        String jwtString = sdJwt.getCredentialJwt();

        // Parse the JWT
        SignedJWT signedJWT = SignedJWT.parse(jwtString);

        // Print JWT Header
        System.out.println("JWT Header:");
        JWSHeader header = signedJWT.getHeader();
        System.out.println(header.toJSONObject());

        // Print JWT Payload
        System.out.println("JWT Payload:");
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        System.out.println(claimsSet.toJSONObject());

        // Print disclosures
        List<Disclosure> disclosures = sdJwt.getDisclosures();
        System.out.println("Disclosures:");
        for (Disclosure disclosure : disclosures) {
            System.out.println(disclosure.getClaimName() + ": " + disclosure.getClaimValue());
        }

        // Verify the JWT signature
        JWSVerifier verifier = new MACVerifier(SHARED_SECRET.getBytes());
        if (signedJWT.verify(verifier)) {
            System.out.println("Signature: VALID");
        } else {
            System.out.println("Signature: INVALID");
        }
    }
}
