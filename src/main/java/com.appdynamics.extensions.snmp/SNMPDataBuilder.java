package com.appdynamics.extensions.snmp;


import com.appdynamics.extensions.alerts.customevents.*;
import com.appdynamics.extensions.snmp.api.*;
import com.appdynamics.extensions.snmp.config.Configuration;
import com.appdynamics.extensions.snmp.config.ControllerConfig;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.log4j.Logger;

import java.util.List;
import java.util.Map;

public class SNMPDataBuilder {

    public static final Joiner JOIN_ON_COMMA = Joiner.on(",");
    private Configuration config;
    private IService service = new ServiceImpl();
    private final HttpClientBuilder clientBuilder;
    private final EndpointBuilder endpointBuilder;

    private static Logger logger = Logger.getLogger(SNMPDataBuilder.class);


    public SNMPDataBuilder(Configuration config) {
        this.config = config;
        ControllerConfig controller = config.getController();
        clientBuilder = new HttpClientBuilder(controller.isUseSsl(), controller.getUserAccount(), controller.getPassword(), controller.getConnectTimeoutInSeconds() * 1000, controller.getSocketTimeoutInSeconds() * 1000);
        endpointBuilder = new EndpointBuilder();
    }


    public ADSnmpData buildFromHealthRuleViolationEvent(HealthRuleViolationEvent violationEvent){
        ADSnmpData snmpData = new ADSnmpData();
        snmpData.setApplication(violationEvent.getAppName());
        snmpData.setTriggeredBy(violationEvent.getHealthRuleName());
        snmpData.setEventTime(violationEvent.getPvnAlertTime());
        snmpData.setSeverity(violationEvent.getSeverity());
        snmpData.setType(violationEvent.getAffectedEntityType());
        snmpData.setSubtype(" ");
        snmpData.setSummary(violationEvent.getSummaryMessage());
        if (config.getController() != null) {
            snmpData.setLink(CommonUtils.getAlertUrl(violationEvent));
        }
        snmpData.setTag(violationEvent.getTag());
        snmpData.setEventType(violationEvent.getEventType());
        snmpData.setIncidentId(violationEvent.getIncidentID());
        snmpData.setAccountId(CommonUtils.cleanUpAccountInfo(violationEvent.getAccountId()));
        //get BTs
        List<String> bts = getBTs(violationEvent);
        snmpData.setTxns( JOIN_ON_COMMA.join((bts)));
        //get nodes
        List<String> nodes = getNodes(violationEvent);
        snmpData.setNodes( JOIN_ON_COMMA.join((nodes)));

        //get tiers
        List<String> tiers = getTiers(violationEvent);
        snmpData.setTiers( JOIN_ON_COMMA.join((tiers)));

        //get ip addresses and populate ip addresses, machine names
        if(config.isFetchMachineInfoFromApi()){
            populateMachineInfo(violationEvent, nodes, tiers, snmpData);
        }
        return snmpData;
    }

    //There is a possibility that we may not have enough tier and node context in custom action.
    //This is because of a bug in controller. The controller should at least send tier level info.
    //It is not feasible to get just add all nodes and tiers if we are not able to resolve because that
    //list could be huge.
    private void populateMachineInfo(HealthRuleViolationEvent violationEvent, List<String> nodes, List<String> tiers, ADSnmpData snmpData) {
        //get all nodes in this application
        logger.debug("Tiers : " + tiers);
        logger.debug("Nodes : " + nodes);
        List<Node> allNodes = getAllNodesInApplication(violationEvent);
        Map<String,Node> nodeMap = createNodeMap(allNodes);
        if(!nodes.isEmpty() && tiers.isEmpty()){
            List<String> tiersForNode = Lists.newArrayList();
            List<String> machines = Lists.newArrayList();
            List<String> ipAddresses = Lists.newArrayList();
            for(String name : nodes){
                Node node = nodeMap.get(name);
                if(node != null){
                    tiersForNode.add(node.getTierName());
                    ipAddresses.addAll(node.getIpAddresses());
                    machines.add(node.getMachineName());
                }
            }
            snmpData.setTiers(JOIN_ON_COMMA.join((tiersForNode)));
            snmpData.setMachines(JOIN_ON_COMMA.join(machines));
            snmpData.setIpAddresses(JOIN_ON_COMMA.join(ipAddresses));
        }
        else if(!nodes.isEmpty() && !tiers.isEmpty()){
            List<String> machines = Lists.newArrayList();
            List<String> ipAddresses = Lists.newArrayList();
            for(String name : nodes){
                Node node = nodeMap.get(name);
                if(node != null){
                    ipAddresses.addAll(node.getIpAddresses());
                    machines.add(node.getMachineName());
                }
            }
            snmpData.setMachines(JOIN_ON_COMMA.join(machines));
            snmpData.setIpAddresses(JOIN_ON_COMMA.join(ipAddresses));
        }
        else {
            logger.debug("More information on the tiers and nodes cannot be resolved");
        }

    }

    private Map<String, Node> createNodeMap(List<Node> allNodes) {

        Map<String,Node> nodeMap = Maps.newHashMap();
        for(Node node : allNodes){
            nodeMap.put(node.getName(),node);
        }
        return nodeMap;
    }

    private List<Node> getAllNodesInApplication(HealthRuleViolationEvent violationEvent) {
        ControllerConfig controller = config.getController();
        String endpoint = endpointBuilder.buildNodesEndpoint(controller, Integer.parseInt(violationEvent.getAppID()));
        List<Node> nodes = service.getNodes(clientBuilder,endpoint);
        return nodes;
    }

    private String getTiersFromBTApi(HealthRuleViolationEvent violationEvent) {
        ControllerConfig controller = config.getController();
        String endpoint = endpointBuilder.buildBTsEndpoint(controller,Integer.parseInt(violationEvent.getAppID()));
        List<BusinessTransaction> bts = service.getBTs(clientBuilder,endpoint);
        for(BusinessTransaction bt : bts){
            if(bt.getId() == Integer.parseInt(violationEvent.getAffectedEntityID())){
                return bt.getTierName();
            }
        }
        return "";
    }


    public ADSnmpData buildFromOtherEvent(OtherEvent otherEvent){
        ADSnmpData snmpData = new ADSnmpData();
        snmpData.setApplication(otherEvent.getAppName());
        snmpData.setTriggeredBy(otherEvent.getEventNotificationName());
        snmpData.setNodes(" ");
        snmpData.setTxns(" ");
        snmpData.setMachines(" ");
        snmpData.setTiers(" ");
        snmpData.setEventTime(otherEvent.getEventNotificationTime());
        snmpData.setSeverity(otherEvent.getSeverity());
        snmpData.setType(getTypes(otherEvent));
        snmpData.setSubtype(" ");
        snmpData.setSummary(getSummary(otherEvent));
        if(config.getController() != null) {
            snmpData.setLink(CommonUtils.getAlertUrl(otherEvent));
        }
        snmpData.setTag(otherEvent.getTag());
        snmpData.setEventType("NON-POLICY-EVENT");
        snmpData.setIncidentId(otherEvent.getEventNotificationId());
        snmpData.setAccountId(CommonUtils.cleanUpAccountInfo(otherEvent.getAccountId()));
        return snmpData;
    }



    private List<String> getNodes(HealthRuleViolationEvent violationEvent) {
        List<String> nodes = Lists.newArrayList();
        if(isAffectedEntityType(violationEvent, "APPLICATION_COMPONENT_NODE")){
            nodes.add(violationEvent.getAffectedEntityName());
        }
        else if(violationEvent.getEvaluationEntity() != null) {
            for (EvaluationEntity evaluationEntity : violationEvent.getEvaluationEntity()) {
                if (evaluationEntity.getType().equalsIgnoreCase("APPLICATION_COMPONENT_NODE")) {
                    nodes.add(evaluationEntity.getName());
                }
            }
        }
        return nodes;
    }

    private boolean isAffectedEntityType(HealthRuleViolationEvent violationEvent, String type) {
        if(type.equalsIgnoreCase(violationEvent.getAffectedEntityType())){
            return true;
        }
        return false;
    }

    private boolean isClosedOrCancelledEvent(HealthRuleViolationEvent violationEvent) {
        if(violationEvent.getEventType().startsWith(EventTypeEnum.POLICY_CANCELED.name()) || violationEvent.getEventType().startsWith(EventTypeEnum.POLICY_CLOSE.name())){
            return true;
        }
        return false;
    }

    private List<String> getBTs(HealthRuleViolationEvent violationEvent) {
        List<String> bts = Lists.newArrayList();
        if(isAffectedEntityType(violationEvent, "BUSINESS_TRANSACTION")){
            bts.add(violationEvent.getAffectedEntityName());
        }
        else if(violationEvent.getEvaluationEntity() != null) {
            for (EvaluationEntity evaluationEntity : violationEvent.getEvaluationEntity()) {
                if (evaluationEntity.getType().equalsIgnoreCase("BUSINESS_TRANSACTION")) {
                    bts.add(evaluationEntity.getName());
                }
            }
        }
        return bts;
    }

    private List<String> getTiers(HealthRuleViolationEvent violationEvent) {
        List<String> tiers = Lists.newArrayList();
        if(isAffectedEntityType(violationEvent, "APPLICATION_COMPONENT")){
            tiers.add(violationEvent.getAffectedEntityName());
        }
        else if(violationEvent.getEvaluationEntity() != null) {
            for (EvaluationEntity evaluationEntity : violationEvent.getEvaluationEntity()) {
                if (evaluationEntity.getType().equalsIgnoreCase("APPLICATION_COMPONENT")) {
                    tiers.add(evaluationEntity.getName());
                }
            }
        }
        //for BTs, when the health rule is configured to be triggered when the condition fails on
        // avergae number of nodes in the tier, the controller doesn't pass tier name but just the application name.
        //In such cases, tier name needs to be pulled from API.
        if(tiers.isEmpty() && isAffectedEntityType(violationEvent,"BUSINESS_TRANSACTION")){
            String btTiers = getTiersFromBTApi(violationEvent);
            if(!Strings.isNullOrEmpty(btTiers)){
                tiers.add(btTiers);
            }
        }
        return tiers;
    }




    private String getSummary(OtherEvent otherEvent) {
        StringBuilder summaries = new StringBuilder("");
        if(otherEvent.getEventSummaries() != null){
            for(EventSummary eventSummary : otherEvent.getEventSummaries()){
                summaries.append(eventSummary.getEventSummaryString()).append(" ");
            }
        }
        return summaries.toString();
    }


    private String getTypes(OtherEvent otherEvent) {
        StringBuilder types = new StringBuilder("");
        if(otherEvent.getEventTypes() != null){
            for(EventType eventType : otherEvent.getEventTypes()){
                types.append(eventType.getEventType()).append(" ");
            }
        }
        return types.toString();
    }




}
