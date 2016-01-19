package com.appdynamics.extensions.api;


import com.appdynamics.extensions.alerts.customevents.HealthRuleViolationEvent;
import com.appdynamics.extensions.snmp.CommonUtils;
import org.junit.Assert;
import org.junit.Test;

public class CommonUtilsTest {

    @Test
    public void testAlertUrl(){
        HealthRuleViolationEvent event = new HealthRuleViolationEvent();
        event.setDeepLinkUrl("https://localhost:8080/#location=APP_INCIDENT_DETAIL&incident=");
        event.setIncidentID("12345");
        String url = CommonUtils.getAlertUrl("appd-pre.ei.eventsgslb.ibm.com","8181",event);
        Assert.assertTrue(url.equalsIgnoreCase("https://appd-pre.ei.eventsgslb.ibm.com:8181/#location=APP_INCIDENT_DETAIL&incident=12345"));
    }

    @Test
    public void testCleanupAccountInfo(){
        String accountId = "JAMS_034cda68-fb5c-4914-b161-5a35eff69a6c";
        String accountName = CommonUtils.cleanUpAccountInfo(accountId);
        Assert.assertTrue(accountName.equalsIgnoreCase("JAMS"));
    }

}
