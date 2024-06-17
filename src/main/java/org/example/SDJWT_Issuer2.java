package org.example;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.IOException;
import java.util.*;

public class SDJWT_Issuer2 {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter user ID for Issuer2: ");
        String userId = scanner.nextLine();

        String sharedSecret = SharedKeyManager.getSharedKey(userId+"_issuer2");
        if (sharedSecret == null) {
            System.out.print("Shared key not found. Enter a new shared key: ");
            sharedSecret = scanner.nextLine();
            try {
                SharedKeyManager.addOrUpdateSharedKey(userId+"_issuer2", sharedSecret);
            } catch (IOException e) {
                System.err.println("Failed to save shared key: " + e.getMessage());
                return;
            }
        }

        try {
            Map<String, Object> jsonData = collectDataFromUser();

            List<Disclosure> disclosures = createDisclosures(jsonData);

            String credentialJwt = generateCredentialJWT(disclosures, sharedSecret);

            SDJWT sdJwt = new SDJWT(credentialJwt, disclosures);

            System.out.println("SD-JWT:");
            System.out.println(sdJwt.toString());
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static Map<String, Object> collectDataFromUser() {
        Scanner scanner = new Scanner(System.in);
        Map<String, Object> jsonData = new LinkedHashMap<>();

        System.out.println("Enter the following details for the PAN Card:");

        System.out.print("Full name: ");
        jsonData.put("Full_name", scanner.nextLine());

        System.out.print("Gender: ");
        jsonData.put("Gender", scanner.nextLine());

        System.out.print("Date of birth: ");
        jsonData.put("Date_of_birth", scanner.nextLine());

        System.out.print("PAN number: ");
        jsonData.put("PAN_number", scanner.nextLine());

        System.out.print("Issue date: ");
        jsonData.put("Issue_date", scanner.nextLine());

        return jsonData;
    }

    private static List<Disclosure> createDisclosures(Map<String, Object> jsonData) {
        List<Disclosure> disclosures = new ArrayList<>();
        for (Map.Entry<String, Object> entry : jsonData.entrySet()) {
            String key = entry.getKey();
            String value = Base64.getEncoder().encodeToString(((String) entry.getValue()).getBytes());
            disclosures.add(new Disclosure(key, value));
        }
        return disclosures;
    }

    private static String generateCredentialJWT(List<Disclosure> disclosures, String sharedSecret) throws JOSEException {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        for (Disclosure disclosure : disclosures) {
            claimsBuilder.claim(disclosure.getClaimName(), disclosure.getClaimValue());
        }
        JWTClaimsSet claimsSet = claimsBuilder.build();

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new MACSigner(sharedSecret.getBytes()));

        return signedJWT.serialize();
    }
}
