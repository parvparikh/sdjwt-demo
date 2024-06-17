package org.example;

import com.authlete.sd.SDJWT;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.json.JSONObject;

import java.io.*;
import java.net.Socket;
import java.util.*;

public class SDJWT_Holder {

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            List<SDJWT> sdJwts = new ArrayList<>();

            while (true) {
                System.out.println("Enter the SD-JWT (or type 'done' to finish):");
                String jwtString = scanner.nextLine();

                if (jwtString.equalsIgnoreCase("done")) {
                    break;
                }

                try {
                    SDJWT sdJwt = SDJWT.parse(jwtString);
                    sdJwts.add(sdJwt);
                } catch (Exception e) {
                    System.err.println("Error occurred while parsing SD-JWT: " + e.getMessage());
                }
            }

            if (sdJwts.isEmpty()) {
                System.out.println("No SD-JWTs to wrap.");
                return;
            }

            List<Map<String, String>> selectedClaims = new ArrayList<>();
            for (SDJWT sdJwt : sdJwts) {
                Map<String, String> claims = new HashMap<>();
                System.out.println("Select claims for SD-JWT " + sdJwt.toString() + ":");
                String token = sdJwt.getCredentialJwt();
                String[] parts = token.split("\\.");
                String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
                JSONObject payload = new JSONObject(payloadJson);
                for (String claimName : payload.keySet()) {
                    System.out.print("Include claim '" + claimName + "'? (y/n): ");
                    String response = scanner.nextLine();
                    if (response.equalsIgnoreCase("y")) {
                        claims.put(claimName, payload.getString(claimName));
                    }
                }
                selectedClaims.add(claims);
            }
            System.out.println("userId: ");
            String userId = scanner.nextLine();
            String issuer1 = userId + "_issuer1";
            String issuer2 = userId + "_issuer2";

            String issuer1Jwt = null;
            String issuer2Jwt = null;

            if (SharedKeyManager.getSharedKey(issuer1)!= null) {
                issuer1Jwt = generateJWT(selectedClaims.get(0), issuer1);
            }

            if (SharedKeyManager.getSharedKey(issuer2)!= null) {
                issuer2Jwt = generateJWT(selectedClaims.get(1), issuer2);
            }

            JSONObject json = new JSONObject();

            if (issuer1Jwt!= null) {
                json.put("issuer1", issuer1Jwt);
                System.out.println("Using issuer1");
            }

            if (issuer2Jwt!= null) {
                json.put("issuer2", issuer2Jwt);
                System.out.println("Using issuer2");
            }

            if (json.length() == 0) {
                System.out.println("No issuers available.");
                return;
            }

            System.out.println("Final wrapper SD-JWT to send to verifier:");
            System.out.println(json.toString());

            // Sending to verifier
            String address = "localhost";
            int port = 8080;
            sendToVerifier(json.toString(), address, port);

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String generateJWT(Map<String, String> claims, String issuer) throws JOSEException {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        for (Map.Entry<String, String> entry : claims.entrySet()) {
            claimsBuilder.claim(entry.getKey(), entry.getValue());
        }
        JWTClaimsSet claimsSet = claimsBuilder.build();

        // Fetch the shared secret from the shared keys file
        String sharedSecret = SharedKeyManager.getSharedKey(issuer);

        if (sharedSecret == null) {
            throw new RuntimeException("Shared key not found for issuer: " + issuer);
        }

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new MACSigner(sharedSecret.getBytes()));

        return signedJWT.serialize();
    }

    private static void sendToVerifier(String json, String address, int port) {
        try (Socket socket = new Socket(address, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            out.println(json);
            System.out.println("SD-JWT sent to verifier.");

            String response = in.readLine();
            System.out.println("Response from verifier: " + response);

        } catch (IOException e) {
            System.err.println("Error occurred while communicating with verifier: " + e.getMessage());
        }
    }
}
