package org.example;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.print.DocFlavor;
import java.io.IOException;
import java.util.Iterator;

public class KeycloakVerifier {

    private String versionInUse;
    private static JSONArray cves;
    private static JSONArray cvesNoVersion;

    private static JSONArray vulnerabilities;

    private static getVulnerabilityInRecords gve;

    private static produceReport produceReport;


    public KeycloakVerifier( String versionInUse) throws IOException {
        gve= new getVulnerabilityInRecords();
        produceReport=new produceReport();
        this.versionInUse=versionInUse;
        getCVE getCVE = new getCVE();
        cves = getCVE.get();
        verify();
    }

    public KeycloakVerifier(int timeOut, String versionInUse) throws IOException {
        gve= new getVulnerabilityInRecords();
        this.versionInUse=versionInUse;
        getCVE getCVE = new getCVE(timeOut);
        cves = getCVE.get();
        verify();
    }

    private void verify() throws IOException {
        Iterator it= cves.iterator();
        Iterator temp;
        JSONObject cve;
        String product;
        while (it.hasNext()) {
            cve = (JSONObject) it.next();
            JSONObject aux = gve.getVulnerability(cve.getJSONObject("threat_intel").getJSONObject("general").get("cve").toString());

            //quer dizer que não existe este cve no ficheiro de vulnerabilidades
            if (aux == null) {
                    //Vulnerabilidades não existentes no ficheiro vulnerabilities.log
                    analyzeUnknownCVE(cve);
            } else{
                //vulnerabilidade existente no ficheiro vulnerabilities.log
                analyzeCVE(aux);
            }
        }
    }


    private void analyzeCVE(JSONObject cve) throws IOException {
        //checks if are any vulnerabilities with this cve and version
        String version = cve.get("good_version").toString();

        if(isVersionInUseLessThen(version)){
            JSONObject jsonObject = gve.getVulnerability(cve.getString("cve"));
                //vulnerability found on the vulnerabilities file
                if(gve.hasVerificationAvailable(jsonObject.getString("cve").toString())){
                    boolean isActive=false;
                    //call a method that verifies if the vulnerability really occurs
                    switch (cve.getString("cve")){
                        case "CVE-2022-3782":
                            vulnerabilityThree v= new vulnerabilityThree();
                            isActive = v.vulnerabilityThree();
                            break;
                        case "CVE-2020-1717":
                            vulnerabilityOne v1= new vulnerabilityOne();
                            isActive= v1.vulnerabilityOne();
                            break;
                        case "CVE-2021-3754":
                            vulnerabilityTwo v2= new vulnerabilityTwo();
                            isActive=v2.vulnerabilityTwo();
                            break;
                    }
                    if (isActive){
                        //criar um warning com a info
                        warning wrng = new warning();
                        String cveAux=cve.getString("cve");

                        String warning = wrng.addWarning(gve.getValueOf(cveAux,"severity"), gve.getValueOf(cveAux,"message"),gve.getValueOf(cveAux,"solution"),cveAux );
                        produceReport.add(warning);
                    }
                } else{
                    //este é o caso de não existir verificação possivel
                    //neste caso apenas produzir um warning com a info do vulnerabilities.log
                    warning wrng = new warning();
                    String cveAux=cve.getString("cve");
                    String warning = wrng.addWarning(cve.getString("severity"),cve.getString("message"),cve.getString("solution"),cveAux);
                    produceReport.add(warning);
                }
        }
        produceReport.writeReport();
    }


    private boolean isVersionInUseLessOrEqualThen(String version){
        return Integer.parseInt(versionInUse.split("\\.")[0]) <= Integer.parseInt(version.split("\\.")[0]);
    }
    private boolean isVersionInUseLessThen(String version){
        return Integer.parseInt(versionInUse.split("\\.")[0]) < Integer.parseInt(version.split("\\.")[0]);
    }

    /*
    Analyze the cve's that are not on the vulnerabilities.log
     */
    private void analyzeUnknownCVE(JSONObject cve){
        String version=getVersionFixedFromCVE(cve);

        if(!version.equals("") && isVersionInUseLessThen(version)) {
            //System.out.println("CVE:\n"+cve.toString());
            warning wrng = new warning();
            String cveAux = cve.getJSONObject("threat_intel").getJSONObject("general").get("cve").toString();
            String severity = cve.getJSONObject("details").getString("severity");
            String message = cve.getJSONObject("basic").getString("description");
            String warning="";
            if(version.equals("")) {
                warning = wrng.addWarning(severity, message, "", cveAux);

            }
            else{
                String a = "This vulnerability was mitigated on version " + version;
                warning = wrng.addWarning(severity, message, a , cveAux);
            }
            produceReport.add(warning);
            }

        }


    private String getVersionFixedFromCVE(JSONObject cve){
        Iterator nodes = cve.getJSONObject("threat_intel").getJSONObject("general").getJSONObject("configurations").getJSONArray("nodes").iterator();
        JSONObject aux;
        while(nodes.hasNext()){
            aux= (JSONObject) nodes.next();
            Iterator matches = aux.getJSONArray("cpe_match").iterator();
            while (matches.hasNext()){
                JSONObject obj = (JSONObject) matches.next();
                //System.out.println(obj.toString());
                //.out.println(cve.getJSONObject("threat_intel").getJSONObject("general").get("cve").toString());
                String [] split = obj.getString("cpe23Uri").split(":");
                if(split[3].equals("redhat") || split[3].equals("keycloak"))
                    if(split[4].equals("keycloak")){
                        try{
                            return obj.getString("versionEndIncluding");
                        } catch (JSONException e){
                            return "";
                        }
                    }

            }
        }
        return "";
    }

}
