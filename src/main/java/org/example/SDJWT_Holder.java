package org.example;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;

import java.util.*;

public class SDJWT_Holder {

    public static void main(String[] args) {
        try {
            // Example SD-JWT received from the issuer
            String sdJwtString = "eyJhbGciOiJIUzI1NiJ9.eyJSZXNpZGVudHMuUmVzaWRlbnRbMF0uRGF0ZV9vZl9iaXJ0aCI6IjAxLTAxLTE5NzAiLCJSZXNpZGVudHMuUmVzaWRlbnRbMF0uVUlOIjoiOTg3NjU0MzIxMCIsIlJlc2lkZW50cy5SZXNpZGVudFswXS5FbWFpbCI6ImpvaG5kb2VAZW1haWwuY29tIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLmlkIjoiMSIsIlJlc2lkZW50cy5SZXNpZGVudFswXS5TdGF0dXMiOiJWYWxpZCIsIlJlc2lkZW50cy5SZXNpZGVudFswXS5BZGRyZXNzIjoiQWRkcmVzcyAxIG9mIGpvaG4gZG9lIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLlBob25lX251bWJlciI6Ijk4NzY1NDMyMTAiLCJSZXNpZGVudHMuUmVzaWRlbnRbMF0uR2VuZXJhdGVkX29uIjoiMjItMDEtMjAyNCIsIlJlc2lkZW50cy5SZXNpZGVudFswXS5HZW5kZXIiOiJNYWxlIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLklEX3R5cGUiOiJOYXRpb25hbCIsIlJlc2lkZW50cy5SZXNpZGVudFswXS5GdWxsX25hbWUiOiJKb2huIERvZSJ9.ennLANXpusa8wwxbD78jQHJ_yXoRtRYnSBUNzWYWssM~WyI3WktEWjV3RjlHbjdXLUJIYTNTdHR3IiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLmlkIiwiMSJd~WyI2aWszbkR3YVJzMEpwbGw4Tm5uMkNRIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLkZ1bGxfbmFtZSIsIkpvaG4gRG9lIl0~WyJzWHVTNUNPWXA2VVlSQ3J4QVhCdm13IiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLkdlbmRlciIsIk1hbGUiXQ~WyJxTDZERnlrd2FSQlkxSXJpZnFNZmhBIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLkRhdGVfb2ZfYmlydGgiLCIwMS0wMS0xOTcwIl0~WyJ2dVRkMGNfNDhKY0ducWQxbTlDS0R3IiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLklEX3R5cGUiLCJOYXRpb25hbCJd~WyItcU1BdGJwSTBkZlZ4MFhfaDM2ejVRIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLlN0YXR1cyIsIlZhbGlkIl0~WyIyekZNQU1kVDVRUTVTWnRpSDlCSTdnIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLlVJTiIsIjk4NzY1NDMyMTAiXQ~WyJTRzdpM0kzX3l4NDlkQVQtRVNfOTFRIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLlBob25lX251bWJlciIsIjk4NzY1NDMyMTAiXQ~WyJmVGxINm5pU2N6Ui1KRFFMWkVJYUhBIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLkdlbmVyYXRlZF9vbiIsIjIyLTAxLTIwMjQiXQ~WyJXTXlFYlVvaHBMdUdoSk9zMm5Ha2dnIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLkVtYWlsIiwiam9obmRvZUBlbWFpbC5jb20iXQ~WyJ0RldqQWdLdVNUT3dWc3JsYjVRdFpnIiwiUmVzaWRlbnRzLlJlc2lkZW50WzBdLkFkZHJlc3MiLCJBZGRyZXNzIDEgb2Ygam9obiBkb2UiXQ~";
            // Parse the received SD-JWT
            SDJWT sdJwt = SDJWT.parse(sdJwtString);

            // Ask user to select claims to disclose
            List<Disclosure> selectedDisclosures = selectDisclosures(sdJwt);

            // Create a new SD-JWT with selected disclosures
            SDJWT newSdJwt = new SDJWT(sdJwt.getCredentialJwt(), selectedDisclosures);

            // Present the new SD-JWT to verifiers
            System.out.println("Presenting SD-JWT to verifiers with selected disclosures:");
            System.out.println(newSdJwt.toString());
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static List<Disclosure> selectDisclosures(SDJWT sdJwt) {
        List<Disclosure> allDisclosures = sdJwt.getDisclosures();
        List<Disclosure> selectedDisclosures = new ArrayList<>();

        Scanner scanner = new Scanner(System.in);
        System.out.println("Available disclosures:");
        for (int i = 0; i < allDisclosures.size(); i++) {
            System.out.println((i + 1) + ". " + allDisclosures.get(i).getClaimName());
        }

        System.out.println("Enter the numbers of the disclosures to include (comma-separated):");
        String input = scanner.nextLine();
        String[] selectedNumbers = input.split(",");

        for (String numberStr : selectedNumbers) {
            int number = Integer.parseInt(numberStr.trim()) - 1;
            if (number >= 0 && number < allDisclosures.size()) {
                selectedDisclosures.add(allDisclosures.get(number));
            }
        }

        return selectedDisclosures;
    }
}
