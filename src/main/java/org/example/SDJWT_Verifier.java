package org.example;

import com.authlete.sd.SDJWT;
import com.authlete.sd.Disclosure;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.json.JSONObject;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.ParseException;
import java.util.*;

public class SDJWT_Verifier {

    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(8080);
            System.out.println("Verifier started. Waiting for incoming connections...");

            Socket socket = serverSocket.accept();
            System.out.println("Incoming connection from holder.");

            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            String jsonStr = in.readLine();
            JSONObject json = new JSONObject(jsonStr);

            String issuer1Jwt = json.getString("issuer1");
            String issuer2Jwt = json.getString("issuer2");

            JWSVerifier verifierIssuer1 = new MACVerifier("d4a4c1717b71aa81508edccacc2be8ce1c95867bc90d5d3ad33c3cb0a41b3099".getBytes());
            JWSVerifier verifierIssuer2 = new MACVerifier("1234567890abcdef1234567890abcdef".getBytes());

            SignedJWT signedJwt1 = SignedJWT.parse(issuer1Jwt);
            SignedJWT signedJwt2 = SignedJWT.parse(issuer2Jwt);

            if (signedJwt1.verify(verifierIssuer1)) {
                System.out.println("Signature verified with Issuer1's secret: VALID");
                JWTClaimsSet claimsSet1 = signedJwt1.getJWTClaimsSet();
                Map<String, Object> claimsMap1 = claimsSet1.getClaims();
                System.out.println("Claims from Issuer1:");
                for (Map.Entry<String, Object> entry : claimsMap1.entrySet()) {
                    String claimName = entry.getKey();
                    String claimValue = new String(Base64.getDecoder().decode((String) entry.getValue()));
                    System.out.println(claimName + ": " + claimValue);
                }
                out.println("VALID_Issuer1");
            } else {
                System.out.println("Signature verified with Issuer1's secret: INVALID");
                out.println("INVALID_Issuer1");
            }

            if (signedJwt2.verify(verifierIssuer2)) {
                System.out.println("Signature verified with Issuer2's secret: VALID");
                JWTClaimsSet claimsSet2 = signedJwt2.getJWTClaimsSet();
                Map<String, Object> claimsMap2 = claimsSet2.getClaims();
                System.out.println("Claims from Issuer2:");
                for (Map.Entry<String, Object> entry : claimsMap2.entrySet()) {
                    String claimName = entry.getKey();
                    String claimValue = new String(Base64.getDecoder().decode((String) entry.getValue()));
                    System.out.println(claimName + ": " + claimValue);
                }
                out.println("VALID_Issuer2");
            } else {
                System.out.println("Signature verified with Issuer2's secret: INVALID");
                out.println("INVALID_Issuer2");
            }

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }
}