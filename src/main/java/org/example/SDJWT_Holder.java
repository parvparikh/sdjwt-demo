package org.example;

import com.authlete.sd.SDJWT;
import com.authlete.sd.Disclosure;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.json.JSONObject;
import java.io.*;
import java.net.Socket;
import java.text.ParseException;
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

            String issuer1Jwt = generateJWT(selectedClaims.get(0), "issuer1", "d4a4c1717b71aa81508edccacc2be8ce1c95867bc90d5d3ad33c3cb0a41b3099");
            String issuer2Jwt = generateJWT(selectedClaims.get(1), "issuer2", "95c7461240a7194e415341244f3f42e22e59fe35e8f58e61e6e2d0ee75e05a71"); // Replace with your own secret key

            JSONObject json = new JSONObject();
            json.put("issuer1", issuer1Jwt);
            json.put("issuer2", issuer2Jwt);

            System.out.println("Final wrapper SD-JWT to send to verifier:");
            System.out.println(json.toString());

            System.out.println("Enter the verifier's address:");
            String address = scanner.nextLine();
            System.out.println("Enter the verifier's port:");
            int port = Integer.parseInt(scanner.nextLine());

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

    private static String generateJWT(Map<String, String> claims, String issuer, String secretKey) throws JOSEException {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        for (Map.Entry<String, String> entry : claims.entrySet()) {
            claimsBuilder.claim(entry.getKey(), entry.getValue());
        }
        JWTClaimsSet claimsSet = claimsBuilder.build();

        byte[] sharedSecret = secretKey.getBytes();

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new MACSigner(sharedSecret));

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