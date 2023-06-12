package org.example;

import org.json.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class Token {

    private Response resp;
    private static final String URL_TOKEN = "http://localhost:8080/realms/master/protocol/openid-connect/token";

    public Token(){
        resp = new Response();
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

        String response = resp.getResponse(conn);
        JSONObject obj = new JSONObject(response);
        String token = obj.getString("access_token");
        //System.out.println("Token: " + token);
        return token;
    }
}
