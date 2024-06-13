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

public class SDJWT_Issuer1 {
    private static final String JSON_DATA = "{\"License\": {\"Name\": \"John Doe\",\"DOB\": \"01-01-1980\",\"LicenseNumber\": \"DL1234567890\",\"ExpiryDate\": \"01-01-2030\"}}";
    private static final String SHARED_SECRET_ISSUER1 = "d4a4c1717b71aa81508edccacc2be8ce1c95867bc90d5d3ad33c3cb0a41b3099";

    public static void main(String[] args) {
        try {
            Map<String, Object> jsonData = parseJson(JSON_DATA);
            Map<String, Object> allKeys = new LinkedHashMap<>();
            extractKeys("", jsonData, allKeys);

            if (allKeys.isEmpty()) {
                System.err.println("No data found in JSON.");
                return;
            }

            List<Disclosure> disclosures = createDisclosures(allKeys);
            String credentialJwt = generateCredentialJWT(disclosures, SHARED_SECRET_ISSUER1);
            SDJWT sdJwt = new SDJWT(credentialJwt, disclosures);

            System.out.println("SD-JWT from Issuer1:");
            System.out.println(sdJwt.toString());
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static Map<String, Object> parseJson(String jsonContent) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(jsonContent, HashMap.class);
    }

    private static void extractKeys(String prefix, Map<String, Object> jsonData, Map<String, Object> allKeys) {
        for (Map.Entry<String, Object> entry : jsonData.entrySet()) {
            String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Map) {
                extractKeys(key, (Map<String, Object>) value, allKeys);
            } else if (value instanceof List) {
                List<?> list = (List<?>) value;
                for (int i = 0; i < list.size(); i++) {
                    Object item = list.get(i);
                    if (item instanceof Map) {
                        extractKeys(key + "[" + i + "]", (Map<String, Object>) item, allKeys);
                    } else {
                        allKeys.put(key + "[" + i + "]", item);
                    }
                }
            } else {
                allKeys.put(key, value);
            }
        }
    }

    private static List<Disclosure> createDisclosures(Map<String, Object> allKeys) {
        List<Disclosure> disclosures = new ArrayList<>();
        for (Map.Entry<String, Object> entry : allKeys.entrySet()) {
            disclosures.add(new Disclosure(entry.getKey(), Base64.getEncoder().encodeToString(entry.getValue().toString().getBytes())));
        }
        return disclosures;
    }

    private static String generateCredentialJWT(List<Disclosure> disclosures, String secret) throws JOSEException {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        for (Disclosure disclosure : disclosures) {
            claimsBuilder.claim(disclosure.getClaimName(), disclosure.getClaimValue());
        }
        JWTClaimsSet claimsSet = claimsBuilder.build();

        byte[] sharedSecret = secret.getBytes();

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new MACSigner(sharedSecret));

        return signedJWT.serialize();
    }
}
