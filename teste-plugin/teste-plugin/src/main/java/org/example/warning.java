package org.example;

import org.json.JSONObject;

public class warning {

    /*
    severity will be mapped as severity
    description will be mapped as message
    solution will be mapped as description
    category will be mapped as category
     */
    private enum severit {HIGH, LOW, NORMAL};
    public void warning(){}

    public String addWarning(String severity, String description, String solution, String cve){
        String[] temp=severity.split(".");
        String sev;
        int digit1 = Integer.parseInt(temp[0]);
        int digit2 = Integer.parseInt(temp[1]);
        if(digit1>=3 && digit2>=5) {
            if(digit1>=6 && digit2>=5)
                sev = String.valueOf(severit.HIGH);
            else sev = String.valueOf(severit.NORMAL);
        }else sev = String.valueOf(severit.LOW);

        //String s = "{\"fileName\":\""+cve+"\",\"severity\":\""+sev+"\",\"message\":\""+description+"\",\"description\":\""+solution+"\"}";
        String s = "{\"message\":\""+description+"\",\"severity\":\""+sev+"\",\"description\":\""+solution+"\",\"filename\":\""+cve+"\"}";
        return s;
    }
}