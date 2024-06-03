package org.example;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.List;

public class SDJWT_Verifier {

    private static final String SHARED_SECRET = "17627FB44D699A8A29E871FA8EFD8ABCDE0123456789ABCDEF0123456789AB";

    public static void main(String[] args) {
        try {
            // Example SD-JWT received from the holder
            String sdJwtString = "eyJhbGciOiJIUzI1NiJ9.eyJSZXNpZGVudHMuUmVzaWRlbnRbMF0uRGF0ZV9vZl9iaXJ0aCI6IjAxLTAxLTE5NzAiLCJSZXNpZGVudHMuUmVzaWRlbnRbMF0uVUlOIjoiOTg3NjU0MzIxMCIsIlJlc2lkZW50cy5SZXNpZGVudFswXS5FbWFpbCI6ImpvaG5kb2VAZW1haWwuY29tIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLmlkIjoiMSIsIlJlc2lkZW50cy5SZXNpZGVudFswXS5TdGF0dXMiOiJWYWxpZCIsIlJlc2lkZW50cy5SZXNpZGVudFswXS5BZGRyZXNzIjoiQWRkcmVzcyAxIG9mIGpvaG4gZG9lIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLlBob25lX251bWJlciI6Ijk4NzY1NDMyMTAiLCJSZXNpZGVudHMuUmVzaWRlbnRbMF0uR2VuZXJhdGVkX29uIjoiMjItMDEtMjAyNCIsIlJlc2lkZW50cy5SZXNpZGVudFswXS5HZW5kZXIiOiJNYWxlIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLklEX3R5cGUiOiJOYXRpb25hbCIsIlJlc2lkZW50cy5SZXNpZGVudFswXS5GdWxsX25hbWUiOiJKb2huIERvZSJ9.ennLANXpusa8wwxbD78jQHJ_yXoRtRYnSBUNzWYWssM~WyI3WktEWjV3RjlHbjdXLUJIYTNTdHR3IiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLmlkIiwiMSJd~WyJzWHVTNUNPWXA2VVlSQ3J4QVhCdm13IiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLkdlbmRlciIsIk1hbGUiXQ~WyJxTDZERnlrd2FSQlkxSXJpZnFNZmhBIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLkRhdGVfb2ZfYmlydGgiLCIwMS0wMS0xOTcwIl0~WyJ2dVRkMGNfNDhKY0ducWQxbTlDS0R3IiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLklEX3R5cGUiLCJOYXRpb25hbCJd~";

            // Verify the SD-JWT
            verifySDJWT(sdJwtString);
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void verifySDJWT(String sdJwtString) {
        try {
            // Parse the received SD-JWT
            SDJWT sdJwt = SDJWT.parse(sdJwtString);

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
        } catch (Exception e) {
            System.err.println("Error occurred while verifying SD-JWT: " + e.getMessage());
        }
    }
}
