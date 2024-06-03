package junk;

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

public class SDJWT_demo {
    private static final String JSON_DATA = "{\"Residents\": {\"Resident\": [{\"id\": \"1\",\"Full_name\": \"John Doe\",\"Gender\": \"Male\",\"Date_of_birth\": \"01-01-1970\",\"ID_type\": \"National\",\"Status\": \"Valid\",\"UIN\": \"9876543210\",\"Phone_number\": \"9876543210\",\"Generated_on\": \"22-01-2024\",\"Email\": \"johndoe@email.com\",\"Address\": \"Address 1 of john doe\"}]}}";
    private static final String SHARED_SECRET = "17627FB44D699A8A29E871FA8EFD8ABCDE0123456789ABCDEF0123456789AB";

    public static void main(String[] args) {
        try {
            Map<String, Object> jsonData = parseJson(JSON_DATA);

            Map<String, Object> allKeys = new LinkedHashMap<>();
            extractKeys("", jsonData, allKeys);

            if (allKeys.isEmpty()) {
                System.err.println("No data found in JSON.");
                return;
            }

            System.out.println("Available Data:");
            List<String> keys = new ArrayList<>(allKeys.keySet());
            for (int i = 0; i < keys.size(); i++) {
                System.out.println((i + 1) + ". " + keys.get(i) + ": " + allKeys.get(keys.get(i)));
            }

            List<Disclosure> disclosures = createDisclosures(allKeys, keys);
            String credentialJwt = generateCredentialJWT(disclosures);
            SDJWT sdJwt = new SDJWT(credentialJwt, disclosures);

            System.out.println("SD-JWT:");
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

    private static List<Disclosure> createDisclosures(Map<String, Object> allKeys, List<String> keys) {
        List<Disclosure> disclosures = new ArrayList<>();
        Scanner scanner = new Scanner(System.in);

        System.out.println("Select fields to disclose by entering their numbers (comma-separated):");
        String input = scanner.nextLine();
        String[] selectedNumbers = input.split(",");

        for (String numberStr : selectedNumbers) {
            int number = Integer.parseInt(numberStr.trim()) - 1;
            if (number >= 0 && number < keys.size()) {
                String key = keys.get(number);
                Object value = allKeys.get(key);
                if (value instanceof String && key.endsWith("_sd")) {
                    disclosures.add(new Disclosure(key, value.toString()));
                } else if (value instanceof Map && key.endsWith("_sd")) {
                    // Recursively add all sub-fields with _sd suffix
                    extractSdFields(key, (Map<String, Object>) value, disclosures);
                } else {
                    disclosures.add(new Disclosure(key, value.toString()));
                }
            } else {
                System.out.println("Warning: Number '" + (number + 1) + "' is out of range and will be ignored.");
            }
        }

        return disclosures;
    }

    private static void extractSdFields(String prefix, Map<String, Object> jsonData, List<Disclosure> disclosures) {
        for (Map.Entry<String, Object> entry : jsonData.entrySet()) {
            String key = prefix + "." + entry.getKey();
            Object value = entry.getValue();
            if (value instanceof String && key.endsWith("_sd")) {
                disclosures.add(new Disclosure(key, value.toString()));
            } else if (value instanceof Map && key.endsWith("_sd")) {
                // Recursively add all sub-fields with _sd suffix
                extractSdFields(key, (Map<String, Object>) value, disclosures);
            }
        }
    }

    private static String generateCredentialJWT(List<Disclosure> disclosures) throws JOSEException {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        for (Disclosure disclosure : disclosures) {
            claimsBuilder.claim(disclosure.getClaimName(), disclosure.getClaimValue());
        }
        JWTClaimsSet claimsSet = claimsBuilder.build();

        byte[] sharedSecret = SHARED_SECRET.getBytes();

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new MACSigner(sharedSecret));

        return signedJWT.serialize();
    }
}
