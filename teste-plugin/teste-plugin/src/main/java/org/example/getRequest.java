package org.example;


import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class getRequest {
    private static final String URL_TOKEN = "http://localhost:8084/realms/master/protocol/openid-connect/token";
    private static final String URL_VERSION = "http://localhost:8084/admin/serverinfo";

    //private static final String URL_TOKEN = "http://localhost:8080/auth/realms/master/protocol/openid-connect/token";
    //private static final String URL_VERSION = "http://localhost:8080/auth/admin/serverinfo";

    public void getRequest() throws IOException {
    }

    public String getToken() throws IOException {
        URL url = new URL(URL_TOKEN);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);
        String jsonInputString = "username=testuser&password=test&grant_type=password&client_id=admin-rest-client";

        OutputStream os = conn.getOutputStream();
        byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
        os.write(input, 0, input.length);
        os.flush();
        os.close();

        String response = getResponse(conn);
        //System.out.println(response);
        JSONObject obj = new JSONObject(response);
        String token = obj.getString("access_token");
        //System.out.println("Token: " + token);
        return token;
    }

    public String getVersion() throws IOException {
        String token = getToken();
        URL url = new URL(URL_VERSION);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + token);

        String response = getResponse(conn);
        //System.out.println(response);
        JSONObject json = new JSONObject(response);
        String version = json.getJSONObject("systemInfo").getString("version");

        return version;
    }

    private String getResponse(HttpURLConnection conn) {
        BufferedReader in;
        String output;

        try {
            in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        StringBuffer response = new StringBuffer();

        while (true) {
            try {
                if ((output = in.readLine()) == null) break;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            response.append(output);
        }

        try {
            in.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return response.toString();
    }
}

