package com.appdynamics.extensions.snmp;

import com.appdynamics.extensions.alerts.customevents.Event;
import com.appdynamics.extensions.alerts.customevents.HealthRuleViolationEvent;
import com.appdynamics.extensions.alerts.customevents.OtherEvent;
import com.google.common.base.Strings;
import org.apache.log4j.Logger;

public class CommonUtils {

    private static Logger logger = Logger.getLogger(CommonUtils.class);

    public static String getAlertUrl(Event event) {
        String url = event.getDeepLinkUrl();
        if(event instanceof HealthRuleViolationEvent){
            url += ((HealthRuleViolationEvent) event).getIncidentID();
        }
        else{
            url += ((OtherEvent) event).getEventSummaries().get(0).getEventSummaryId();
        }
        return url;
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
