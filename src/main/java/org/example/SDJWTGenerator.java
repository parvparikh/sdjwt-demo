package org.example;

import com.authlete.sd.SDJWT;
import com.authlete.sd.Disclosure;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import java.util.*;

public class SDJWTGenerator {
    public static void main(String[] args) throws Exception {
        String jsonFile = "C:\\Users\\Asus\\IdeaProjects\\demo_Authlete\\src\\main\\java\\org\\example\\Resident.json";
        String jsonContent = readJsonFile(jsonFile);
        Map<String, Object> residentData = parseJson(jsonContent);
        List<Disclosure> disclosures = createDisclosures(residentData);
        String credentialJwt = generateCredentialJWT(residentData);
        SDJWT sdJwt = new SDJWT(credentialJwt, disclosures);
        System.out.println("SD-JWT:");
        System.out.println(sdJwt.toString());
    }
    private static String readJsonFile(String jsonFile) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(jsonFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
        }
        return content.toString();
    }

    private static Map<String, Object> parseJson(String jsonContent) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(jsonContent, HashMap.class);
    }

    private static List<Disclosure> createDisclosures(Map<String, Object> residentData) {
        List<Disclosure> disclosures = new ArrayList<>();
        for (Map.Entry<String, Object> entry : residentData.entrySet()) {
            String fieldName = entry.getKey();
            Object fieldValue = entry.getValue();
            disclosures.add(new Disclosure(fieldName, fieldValue.toString()));
        }
        return disclosures;
    }

    private static String generateCredentialJWT(Map<String, Object> residentData) throws JOSEException {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        for (Map.Entry<String, Object> entry : residentData.entrySet()) {
            claimsBuilder.claim(entry.getKey(), entry.getValue());
        }
        JWTClaimsSet claimsSet = claimsBuilder.build();

        // Replace "secret" with your actual secret key
        byte[] sharedSecret = "17627FB44D699A8A29E871FA8EFC8ABCDE0123456789ABCDEF0123456789AB".getBytes();

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new MACSigner(sharedSecret));

        return signedJWT.serialize();
    }
}
