package org.example;

import com.authlete.sd.SDJWT;
import com.authlete.sd.Disclosure;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.*;

public class SDJWT_Verifier {

    private static final String SHARED_SECRET_ISSUER1 = "d4a4c1717b71aa81508edccacc2be8ce1c95867bc90d5d3ad33c3cb0a41b3099";
    private static final String SHARED_SECRET_ISSUER2 = "95c7461240a7194e415341244f3f42e22e59fe35e8f58e61e6e2d0ee75e05a71";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter the combined SD-JWT:");
        String jwtString = scanner.nextLine();

        try {
            SDJWT sdJwt = SDJWT.parse(jwtString);
            decodeAndVerifySDJWT(sdJwt);
        } catch (JOSEException | ParseException e) {
            System.err.println("Error occurred while decoding SD-JWT: " + e.getMessage());
        }
    }

    private static void decodeAndVerifySDJWT(SDJWT sdJwt) throws ParseException, JOSEException {
        String jwtString = sdJwt.getCredentialJwt();
        SignedJWT signedJWT = SignedJWT.parse(jwtString);

        JWSVerifier verifierIssuer1 = new MACVerifier(SHARED_SECRET_ISSUER1.getBytes());
        JWSVerifier verifierIssuer2 = new MACVerifier(SHARED_SECRET_ISSUER2.getBytes());

        if (signedJWT.verify(verifierIssuer1)) {
            System.out.println("Signature verified with Issuer1's secret: VALID");
        } else if (signedJWT.verify(verifierIssuer2)) {
            System.out.println("Signature verified with Issuer2's secret: VALID");
        } else {
            System.out.println("Signature: INVALID");
            return;
        }

        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        List<Disclosure> disclosures = sdJwt.getDisclosures();

        System.out.println("JWT Header:");
        JWSHeader header = signedJWT.getHeader();
        System.out.println(header.toJSONObject());

        System.out.println("JWT Payload:");
        System.out.println(claimsSet.toJSONObject());

        System.out.println("Disclosures:");
        for (Disclosure disclosure : disclosures) {
            String claimValue = (String) disclosure.getClaimValue();
            String decodedValue = new String(Base64.getDecoder().decode(claimValue.getBytes()));
            System.out.println(disclosure.getClaimName() + ": " + decodedValue);
        }
    }
}
