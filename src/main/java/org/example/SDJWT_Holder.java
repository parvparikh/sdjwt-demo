package org.example;

import com.authlete.sd.SDJWT;
import com.authlete.sd.Disclosure;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.*;
import java.net.Socket;
import java.text.ParseException;
import java.util.*;

public class SDJWT_Holder {

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            List<Disclosure> combinedDisclosures = new ArrayList<>();
            List<String> originalJWTs = new ArrayList<>();

            while (true) {
                System.out.println("Enter the SD-JWT (or type 'done' to finish):");
                String jwtString = scanner.nextLine();

                if (jwtString.equalsIgnoreCase("done")) {
                    break;
                }

                try {
                    SDJWT sdJwt = SDJWT.parse(jwtString);
                    combinedDisclosures.addAll(sdJwt.getDisclosures());
                    originalJWTs.add(jwtString);
                } catch (Exception e) {
                    System.err.println("Error occurred while parsing SD-JWT: " + e.getMessage());
                }
            }

            if (combinedDisclosures.isEmpty()) {
                System.out.println("No disclosures to present.");
                return;
            }

            displayDisclosures(combinedDisclosures);
            System.out.println("Enter the numbers of the claims to include in the final SD-JWT (comma-separated):");
            String input = scanner.nextLine();
            String[] selectedNumbers = input.split(",");

            List<Disclosure> selectedDisclosures = new ArrayList<>();
            for (String numberStr : selectedNumbers) {
                int number = Integer.parseInt(numberStr.trim()) - 1;
                if (number >= 0 && number < combinedDisclosures.size()) {
                    selectedDisclosures.add(combinedDisclosures.get(number));
                } else {
                    System.out.println("Warning: Number '" + (number + 1) + "' is out of range and will be ignored.");
                }
            }

            if (selectedDisclosures.isEmpty()) {
                System.out.println("No disclosures selected.");
                return;
            }

            String combinedCredentialJwt = generateCombinedCredentialJWT(selectedDisclosures);
            SDJWT combinedSdJwt = new SDJWT(combinedCredentialJwt, selectedDisclosures);

            System.out.println("Final combined SD-JWT to send to verifier:");
            System.out.println(combinedSdJwt.toString());

            System.out.println("Enter the verifier's address:");
            String address = scanner.nextLine();
            System.out.println("Enter the verifier's port:");
            int port = Integer.parseInt(scanner.nextLine());

            sendToVerifier(combinedSdJwt.toString(), address, port);

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void displayDisclosures(List<Disclosure> disclosures) {
        System.out.println("Available Disclosures:");
        for (int i = 0; i < disclosures.size(); i++) {
            String claimValue = (String) disclosures.get(i).getClaimValue();
            String decodedValue = new String(Base64.getDecoder().decode(claimValue.getBytes()));
            System.out.println((i + 1) + ". " + disclosures.get(i).getClaimName() + ": " + decodedValue);
        }
    }

    private static String generateCombinedCredentialJWT(List<Disclosure> disclosures) throws JOSEException {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        for (Disclosure disclosure : disclosures) {
            claimsBuilder.claim(disclosure.getClaimName(), disclosure.getClaimValue());
        }
        JWTClaimsSet claimsSet = claimsBuilder.build();

        byte[] sharedSecret = "d4a4c1717b71aa81508edccacc2be8ce1c95867bc90d5d3ad33c3cb0a41b3099".getBytes();

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new MACSigner(sharedSecret));

        return signedJWT.serialize();
    }

    private static void sendToVerifier(String sdJwt, String address, int port) {
        try (Socket socket = new Socket(address, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            out.println(sdJwt);
            System.out.println("SD-JWT sent to verifier.");

            String response = in.readLine();
            System.out.println("Response from verifier: " + response);

        } catch (IOException e) {
            System.err.println("Error occurred while communicating with verifier: " + e.getMessage());
        }
    }
}
