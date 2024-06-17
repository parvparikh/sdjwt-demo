package org.example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.json.JSONObject;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;
import java.util.Scanner;

public class SDJWT_Verifier {

    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(8080);
            System.out.println("Verifier started. Waiting for incoming connections...");

            while (true) {
                try (Socket socket = serverSocket.accept()) {
                    System.out.println("Incoming connection from holder.");

                    try (PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                         BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                         Scanner scanner = new Scanner(System.in)) {

                        // Ask for user ID
                        System.out.print("Enter user ID: ");
                        String userId = scanner.nextLine();

                        // Fetch the shared keys for the given user ID
                        String sharedSecretIssuer1 = SharedKeyManager.getSharedKey(userId + "_issuer1");
                        String sharedSecretIssuer2 = SharedKeyManager.getSharedKey(userId + "_issuer2");

                        if (sharedSecretIssuer1 == null && sharedSecretIssuer2 == null) {
                            System.out.println("Shared key not found for user ID: " + userId);
                            out.println("Shared key not found for user ID: " + userId);
                            continue;
                        }

                        // Read JSON containing JWTs
                        String jsonStr = in.readLine();
                        JSONObject json = new JSONObject(jsonStr);

                        StringBuilder response = new StringBuilder();

                        if (json.has("issuer1") && sharedSecretIssuer1 != null) {
                            String issuer1Jwt = json.getString("issuer1");
                            JWSVerifier verifierIssuer1 = new MACVerifier(sharedSecretIssuer1.getBytes());
                            SignedJWT signedJwt1 = SignedJWT.parse(issuer1Jwt);

                            if (signedJwt1.verify(verifierIssuer1)) {
                                response.append("Issuer1_VALID");
                                System.out.println("Signature verified with Issuer1's secret: VALID");
                                JWTClaimsSet claimsSet1 = signedJwt1.getJWTClaimsSet();
                                Map<String, Object> claimsMap1 = claimsSet1.getClaims();
                                System.out.println("Claims from Issuer1:");
                                for (Map.Entry<String, Object> entry : claimsMap1.entrySet()) {
                                    String claimName = entry.getKey();
                                    String claimValue = new String(Base64.getDecoder().decode((String) entry.getValue()));
                                    System.out.println(claimName + ": " + claimValue);
                                }
                            } else {
                                response.append("Issuer1_INVALID");
                                System.out.println("Signature verified with Issuer1's secret: INVALID");
                            }
                        } else {
                            response.append("Issuer1_NOT_AVAILABLE");
                        }

                        response.append(",");

                        if (json.has("issuer2") && sharedSecretIssuer2 != null) {
                            String issuer2Jwt = json.getString("issuer2");
                            JWSVerifier verifierIssuer2 = new MACVerifier(sharedSecretIssuer2.getBytes());
                            SignedJWT signedJwt2 = SignedJWT.parse(issuer2Jwt);

                            if (signedJwt2.verify(verifierIssuer2)) {
                                response.append("Issuer2_VALID");
                                System.out.println("Signature verified with Issuer2's secret: VALID");
                                JWTClaimsSet claimsSet2 = signedJwt2.getJWTClaimsSet();
                                Map<String, Object> claimsMap2 = claimsSet2.getClaims();
                                System.out.println("Claims from Issuer2:");
                                for (Map.Entry<String, Object> entry : claimsMap2.entrySet()) {
                                    String claimName = entry.getKey();
                                    String claimValue = new String(Base64.getDecoder().decode((String) entry.getValue()));
                                    System.out.println(claimName + ": " + claimValue);
                                }
                            } else {
                                response.append("Issuer2_INVALID");
                                System.out.println("Signature verified with Issuer2's secret: INVALID");
                            }
                        } else {
                            response.append("Issuer2_NOT_AVAILABLE");
                        }

                        // Send the combined result back to the holder
                        out.println(response.toString());

                    } catch (ParseException | JOSEException e) {
                        System.err.println("Verification failed: " + e.getMessage());
                    }
                } catch (IOException e) {
                    System.err.println("Connection handling failed: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Server initialization failed: " + e.getMessage());
        }
    }
}