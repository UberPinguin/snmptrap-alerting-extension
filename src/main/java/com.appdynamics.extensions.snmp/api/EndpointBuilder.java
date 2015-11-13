package com.appdynamics.extensions.snmp.api;


import com.appdynamics.extensions.snmp.config.ControllerConfig;

public class EndpointBuilder {

    public static final String HTTPS = "https://";
    public static final String HTTP = "http://";
    public static final String APP_ID_HOLDER = "<#APP_ID#>";
    public static final String BT_ENDPOINT = "/controller/rest/applications/"+ APP_ID_HOLDER + "/business-transactions";
    public static final String NODES_ENDPOINT = "/controller/rest/applications/"+ APP_ID_HOLDER + "/nodes";

    public String buildBTsEndpoint(ControllerConfig controller,int applicationId) {
        StringBuffer sb = getHost(controller).append(BT_ENDPOINT);
        String endpoint =  sb.toString();
        return endpoint.replaceFirst(APP_ID_HOLDER,Integer.toString(applicationId));
    }

    public String buildNodesEndpoint(ControllerConfig controller,int applicationId) {
        StringBuffer sb = getHost(controller).append(NODES_ENDPOINT);
        String endpoint =  sb.toString();
        return endpoint.replaceFirst(APP_ID_HOLDER,Integer.toString(applicationId));
    }



    private StringBuffer getHost(ControllerConfig controller){
        StringBuffer sb = new StringBuffer();
        if(controller.isUseSsl()){
            sb.append(HTTPS);
        }
        else{
            sb.append(HTTP);
        }
        sb.append(controller.getHost()).append(":").append(controller.getPort());
        return sb;
    }

}
