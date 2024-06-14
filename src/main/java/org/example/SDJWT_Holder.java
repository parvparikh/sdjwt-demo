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

            displaySDJWTS(sdJwts);
            System.out.println("Enter the numbers of the SD-JWTs to include in the wrapper SD-JWT (comma-separated):");
            String input = scanner.nextLine();
            String[] selectedNumbers = input.split(",");

            List<SDJWT> selectedSDJWTS = new ArrayList<>();
            for (String numberStr : selectedNumbers) {
                int number = Integer.parseInt(numberStr.trim()) - 1;
                if (number >= 0 && number < sdJwts.size()) {
                    selectedSDJWTS.add(sdJwts.get(number));
                } else {
                    System.out.println("Warning: Number '" + (number + 1) + "' is out of range and will be ignored.");
                }
            }

            if (selectedSDJWTS.isEmpty()) {
                System.out.println("No SD-JWTs selected.");
                return;
            }

            List<Map<String, String>> selectedClaims = new ArrayList<>();
            for (SDJWT sdJwt : selectedSDJWTS) {
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
            // Generate the final wrapper JWT
            String issuer1Jwt = generateJWT(selectedClaims.get(0), userId+"_issuer1");
            String issuer2Jwt = generateJWT(selectedClaims.get(1), userId+"_issuer2");

            JSONObject json = new JSONObject();
            json.put("issuer1", issuer1Jwt);
            json.put("issuer2", issuer2Jwt);

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

    private static void displaySDJWTS(List<SDJWT> sdJwts) {
        System.out.println("Available SD-JWTs:");
        for (int i = 0; i < sdJwts.size(); i++) {
            System.out.println((i + 1) + ". " + sdJwts.get(i).toString());
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
