package org.example;


import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.json.JSONObject;

import java.io.IOException;

@Mojo(name="test", defaultPhase = LifecyclePhase.INITIALIZE)
public class Main extends AbstractMojo {

    public void execute() {
        getRequest get = new getRequest();
        try {
            KeycloakVerifier verifier = new KeycloakVerifier(get.getVersion());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
