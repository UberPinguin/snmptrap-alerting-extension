package com.appdynamics.extensions.snmp;

import com.appdynamics.extensions.alerts.customevents.Event;
import com.appdynamics.extensions.alerts.customevents.HealthRuleViolationEvent;
import com.appdynamics.extensions.alerts.customevents.OtherEvent;
import com.google.common.base.Strings;
import org.apache.log4j.Logger;

public class CommonUtils {

    private static Logger logger = Logger.getLogger(CommonUtils.class);

    public static String getAlertUrl(String controllerHost,String controllerPort, Event event) {
        String url = event.getDeepLinkUrl();
        if(Strings.isNullOrEmpty(controllerHost) || Strings.isNullOrEmpty(controllerPort)){
            logger.debug("ControllerHost and/or ControllerPort not configured correctly.");
            return url;
        }
        int startIdx = 0;
        if(url.startsWith("http://")){
            startIdx = "http://".length();
        }
        else if(url.startsWith("https://")){
            startIdx = "https://".length();
        }
        int endIdx = url.indexOf("/",startIdx + 1);
        String toReplace = url.substring(startIdx,endIdx);
        String alertUrl = url.replaceFirst(toReplace,controllerHost + ":" + controllerPort);
        if(event instanceof HealthRuleViolationEvent){
            alertUrl += ((HealthRuleViolationEvent) event).getIncidentID();
        }
        else{
            alertUrl += ((OtherEvent) event).getEventSummaries().get(0).getEventSummaryId();
        }
        return alertUrl;
    }

    public static String cleanUpAccountInfo(String accountId) {
        if(Strings.isNullOrEmpty(accountId)){
            return "";
        }
        int idx = accountId.indexOf("_");
        if(idx != -1){
            return accountId.substring(0,idx);
        }
        return accountId;
    }
}
