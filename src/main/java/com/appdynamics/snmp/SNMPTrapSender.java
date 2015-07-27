/**
 * Copyright 2013 AppDynamics
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */




package com.appdynamics.snmp;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.lang.reflect.Field;
import java.util.*;
import java.util.zip.DataFormatException;

import org.apache.log4j.Logger;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.PDUv1;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.IpAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import com.appdynamics.Lookup.Lookup;
import com.appdynamics.REST.RESTToolkit;
import com.appdynamics.snmp.type.ADSnmpData;
import com.appdynamics.snmp.util.CustomNotification;

/**
 * Java class allows sending SNMP Traps
 */
public class SNMPTrapSender extends CustomNotification
{

    private static final String TRAP_OID_01 = "1.3.6.1.4.1.40684.1.1.1.500.1";
    private static final String TRAP_OID_02 = "1.3.6.1.4.1.40684.1.1.1.500.2";
    private static final String TRAP_OID_03 = "1.3.6.1.4.1.40684.1.1.1.500.3";
    private static final String TRAP_OID_04 = "1.3.6.1.4.1.40684.1.1.1.500.4";
    private static final String TRAP_OID_05 = "1.3.6.1.4.1.40684.1.1.1.500.5";
    private static final String TRAP_OID_06 = "1.3.6.1.4.1.40684.1.1.1.500.6";
    private static final String TRAP_OID_07 = "1.3.6.1.4.1.40684.1.1.1.500.7";
    private static final String TRAP_OID_08 = "1.3.6.1.4.1.40684.1.1.1.500.8";
    private static final String TRAP_OID_09 = "1.3.6.1.4.1.40684.1.1.1.500.9";
    private static final String TRAP_OID_10 = "1.3.6.1.4.1.40684.1.1.1.500.10";


    private static String TRAP_OID = TRAP_OID_01;

    private static Logger logger = Logger.getLogger(SNMPTrapSender.class);
    private static boolean bLogging = true;

    public static String SNMP_V1 = "1";
    public static String SNMP_V2 = "2";
    public static String SNMP_V3 = "3";

    public static String NO_AUTH_NO_PRIV = "1";
    public static String AUTH_NO_PRIV = "2";
    public static String AUTH_PRIV = "3";

    public static String CONTROLLER_HOST;
    public static String CONTROLLER_PORT;
    public static String CONTROLLER_USERNAME;
    public static String CONTROLLER_PASSWORD;

    public static int MIB_VERSION;
    public static boolean SUPPRESS_NON_POLICY_EVENTS = false;

    /**
     * Main class that accepts command line arguments and assigns them to the
     * SNMP Data object
     * @param 	args		Command line arguments
     * @throws 				Exception
     */
    public static void main(String args[]) throws InvalidObjectException
    {
        try
        {

            logInfo("Starting to parse config");

            String SNMPTrapSenderHome = System.getProperty("SNMP_TRAP_SENDER_HOME");

            Map<String, String> config = parseXML(SNMPTrapSenderHome + "/conf/config.xml");

            logInfo("Parsing config complete");

            bLogging = Boolean.parseBoolean(config.get("enable-logs"));

            if (!(config.containsKey("receiver-host") || config.containsKey("receiver-port")))
            {
                logger.error("Cannot read values from config file. Please verify that the values for receiver-host and receiver-port are set");
                throw new InvalidObjectException("Cannot read values from config file. Please verify that the values for receiver-host and receiver-port are set");
            }
            if (!(config.containsKey("controller-host") || config.containsKey("controller-port")))
            {
                logger.error("Cannot read values from config file. Please verify that the values for controller-host and controller-port are set");
                throw new InvalidObjectException("Cannot read values from config file. Please verify that the values for controller-host and controller-port are set");
            }
            if (!(config.containsKey("controller-username") || config.containsKey("controller-password")))
            {
                logger.error("Cannot read values from config file. Please verify that the values for controller-username and controller-password are set");
                throw new InvalidObjectException("Cannot read values from config file. Please verify that the values for controller-username and controller-password are set");
            }

            String host = config.get("receiver-host");
            String port = config.get("receiver-port");
            String trapHost = config.get("sender-host");
            CONTROLLER_HOST = config.get("controller-host");
            CONTROLLER_PORT = config.get("controller-port");
            CONTROLLER_USERNAME = config.get("controller-username");
            CONTROLLER_PASSWORD = config.get("controller-password");

            String mibVersion = config.get("mib-version");
            if (mibVersion != null) {
                if (mibVersion.equals("2")) {
                    MIB_VERSION = 2;
                } else if (mibVersion.equals("3")) {
                    MIB_VERSION = 3;
                } else {
                    MIB_VERSION = 1;
                }
            } else {
                MIB_VERSION = 1;
            }

            String suppressEvents = config.get("suppress-non-policy-events");
            if (suppressEvents != null && suppressEvents.equals("true")) {
                SUPPRESS_NON_POLICY_EVENTS = true;
            }

            String community = (!config.containsKey("community") || config.get("community").toString().equals("")) ?
                    "PUBLIC" : config.get("community");
            String snmp_ver = config.get("snmp-version");

            removeDoubleQuotes(args);

            parseArgs(args);

            logInfo("Finished parsing arguments");

            ADSnmpData snmpData = new ADSnmpData();
            if (IS_HEALTH_RULE_VIOLATION) {
                snmpData.application = APP_NAME;
                snmpData.triggeredBy = POLICY_NAME;
                snmpData.nodes = NODES;
                snmpData.BTs = BTs;
                snmpData.machines = MACHINES;
                snmpData.tiers = TIERS;
                snmpData.eventTime = PVN_ALERT_TIME;
                snmpData.severity = SEVERITY;
                snmpData.type = AFFECTED_ENTITY_TYPE;
                snmpData.subtype = " ";
                snmpData.summary = SUMMARY_MESSAGE;
                snmpData.link = DEEP_LINK_URL;
                snmpData.tag = TAG;
                snmpData.eventType = HR_EVENT_TYPE;
                snmpData.incidentId = INCIDENT_ID;
                snmpData.ipAddresses = IP_ADDRESSES;
            } else {
                snmpData.application = APP_NAME;
                snmpData.triggeredBy = EN_NAME;
                snmpData.nodes = " ";
                snmpData.BTs = " ";
                snmpData.machines = " ";
                snmpData.tiers = " ";
                snmpData.eventTime = EN_TIME;
                snmpData.severity = SEVERITY;
                String types = "";
                for (Event_Type type : event_types){
                    types += type.EVENT_TYPE + " ";
                }
                snmpData.type = types;
                snmpData.subtype = " ";
                String summaries = "";
                for (Event_Summary summary : event_summaries){
                    summaries += summary.EVENT_SUMMARY_STRING + ". ";
                }
                snmpData.summary = summaries;
                snmpData.link = DEEP_LINK_URL;
                snmpData.tag = TAG;
                snmpData.eventType = "NON-POLICY-EVENT";
                snmpData.incidentId = EN_ID;

            }

            logInfo("------------SNMP Trap Data-------------");
            for (Field field : snmpData.getClass().getFields())
            {
                try {
                    logInfo(field.getName() + ": " + field.get(snmpData).toString());
                } catch (Throwable ex) {
                    logger.error("Error reading snmp data fields", ex);
                }

            }

            if (IS_HEALTH_RULE_VIOLATION || (!SUPPRESS_NON_POLICY_EVENTS)) {

                logInfo("--------------------------------------");
                logInfo("------------Sending Trap--------------");

                if (snmp_ver.equals(SNMP_V1)) {
                    new SNMPTrapSender().sendV1Trap(host, port, community, trapHost, snmpData);
                } else if (snmp_ver.equals(SNMP_V2)) {
                    new SNMPTrapSender().sendV2Trap(host, port, community, trapHost, snmpData);
                } else if (snmp_ver.equals(SNMP_V3)) {
                    new SNMPTrapSender().sendV3Trap(host, port, trapHost, snmpData, config);
                } else {
                    logger.error("Invalid SNMP Trap Version: " + snmp_ver);
                    throw new InvalidObjectException("Invalid SNMP Trap Version: " + snmp_ver);
                }

                logInfo("-------------Trap Sent!---------------");
            }


        } catch (DataFormatException e) {
            logger.error("Unable to parse arguments: " + e.getMessage());
        } catch (DocumentException doc) {
            logger.error("Cannot read or find config.xml.");
        } catch (IOException e) {
            logger.error("Failed to send trap: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("Failed to access SNMP Data Variable: " + e.getMessage());
        } catch (IllegalAccessException e) {
            logger.error("Failed to access SNMP Data Variable: " + e.getMessage());
        } catch (Throwable ex) {
            ex.printStackTrace();
            logger.fatal("Fatal Error: ", ex);
        }


    }

    /**
     * Sends v1 Traps
     * @param 	host 						Host to send trap to
     * @param 	port						Port location to send trap to
     * @param 	community					Community (Default: PUBLIC)
     * @param 	trapHost					Host of the source sending the trap
     * @param 	snmpData					Trap Data
     * @throws 	IOException					Failed to send trap exception
     * @throws 	IllegalArgumentException 	Failed to access snmp trap variables
     * @throws 	IllegalAccessException 		Failed to access snmp trap variables
     */
    @SuppressWarnings("rawtypes")
    public void sendV1Trap(String host, String port, String community, String trapHost, ADSnmpData snmpData)
            throws IOException, IllegalArgumentException, IllegalAccessException
    {
        Lookup lookUp = new Lookup();

        TransportMapping transport = new DefaultUdpTransportMapping();
        transport.listen();

        CommunityTarget comTarget = new CommunityTarget();
        comTarget.setCommunity(new OctetString(community));
        comTarget.setVersion(SnmpConstants.version1);
        comTarget.setAddress(new UdpAddress(host + "/" + port));
        comTarget.setRetries(2);
        comTarget.setTimeout(5000);

        PDUv1 pdu = new PDUv1();
        pdu.setType(PDU.V1TRAP);
        pdu.setEnterprise(new OID(TRAP_OID));
        pdu.setGenericTrap(PDUv1.ENTERPRISE_SPECIFIC);
        pdu.setSpecificTrap(1);
        pdu.setAgentAddress(new IpAddress(trapHost));
        pdu.add(new VariableBinding(SnmpConstants.sysUpTime,  new OctetString(new Date().toString())));
        pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(TRAP_OID)));
        pdu.add(new VariableBinding(SnmpConstants.snmpTrapAddress, new IpAddress(trapHost)));

        for (Field field : snmpData.getClass().getDeclaredFields())
        {
            if(field.get(snmpData) != null) {
                try {
                    Object snmpVal = new OctetString(field.get(snmpData).toString());

                    if (!(snmpVal.equals(" ") || snmpVal.equals(""))) {
                        pdu.add(new VariableBinding(new OID(lookUp.getOID(field.getName())), new OctetString(snmpVal.toString())));
                    }
                } catch (Throwable ex) {
                    logger.error("Error reading snmp data field:", ex);
                }
            }
        }

        Snmp snmp = new Snmp(transport);
        snmp.send(pdu, comTarget);
        snmp.close();
    }

    /**
     * Sends v2 Traps
     * @param 	host 						Host to send trap to
     * @param 	port						Port location to send trap to
     * @param 	community					Community (Default: PUBLIC)
     * @param 	trapHost					Host of the source sending the trap
     * @param 	snmpData					Trap Data
     * @throws 	IOException					Failed to send trap exception
     * @throws 	IllegalArgumentException 	Failed to access snmp trap variables
     * @throws 	IllegalAccessException 		Failed to access snmp trap variables
     */
    @SuppressWarnings("rawtypes")
    public void sendV2Trap(String host, String port, String community, String trapHost, ADSnmpData snmpData)
            throws IOException, IllegalArgumentException, IllegalAccessException
    {
        Lookup lookUp = new Lookup();

        TransportMapping transport = new DefaultUdpTransportMapping();
        transport.listen();

        CommunityTarget comTarget = new CommunityTarget();
        comTarget.setCommunity(new OctetString(community));
        comTarget.setVersion(SnmpConstants.version2c);
        comTarget.setAddress(new UdpAddress(host + '/' + port));
        comTarget.setRetries(2);
        comTarget.setTimeout(5000);

        PDU pdu = new PDU();
        pdu.add(new VariableBinding(SnmpConstants.sysUpTime,  new OctetString(new Date().toString())));
        pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(TRAP_OID)));
        pdu.add(new VariableBinding(SnmpConstants.snmpTrapAddress, new IpAddress(trapHost)));

        for (Field field : snmpData.getClass().getDeclaredFields())
        {
            if(field.get(snmpData) != null) {

                try {
                    Object snmpVal = new OctetString(field.get(snmpData).toString());

                    if (!(snmpVal.equals(" ") || snmpVal.equals(""))) {
                        pdu.add(new VariableBinding(new OID(lookUp.getOID(field.getName())), new OctetString(snmpVal.toString())));
                    }
                } catch (Throwable ex) {
                    logger.error("Error reading snmp data field:", ex);
                }
            }
        }

        pdu.setType(PDU.NOTIFICATION);

        Snmp snmp = new Snmp(transport);
        snmp.send(pdu, comTarget);
        snmp.close();
    }

    /**
     * Sends v3 Traps
     * @param 	host 					Host to send trap to
     * @param 	port					Port location to send trap to
     * @param 	trapHost				Host of the source sending the trap
     * @param 	snmpData				Trap Data
     * @param 	settings				V3 settings
     * @throws 	IOException					Failed to send trap exception
     * @throws 	IllegalArgumentException 	Failed to access snmp trap variables
     * @throws 	IllegalAccessException 		Failed to access snmp trap variables
     */
    @SuppressWarnings("rawtypes")
    public void sendV3Trap(String host, String port, String trapHost, ADSnmpData snmpData, Map<String, String> settings)
            throws IOException, IllegalArgumentException, IllegalAccessException
    {
        Lookup lookup = new Lookup();

        TransportMapping transport = new DefaultUdpTransportMapping();
        transport.listen();

        byte[] defaultEngineId = MPv3.createLocalEngineID();
        String engineIdFromConfig = settings.get("config-engine-id");
        if(engineIdFromConfig != null && !engineIdFromConfig.isEmpty()){
            defaultEngineId = engineIdFromConfig.getBytes();
        }

        MPv3 mpv3 = new MPv3(defaultEngineId);

        USM usm = new USM
                (
                        SecurityProtocols.getInstance(),
                        new OctetString(mpv3.getLocalEngineID()),
                        0
                );

        SecurityModels.getInstance().addSecurityModel(usm);

        Snmp snmp = new Snmp(transport);
        String securityLevel = settings.get("security-level");

        if(securityLevel.equals(NO_AUTH_NO_PRIV))
        {
            snmp.getUSM().addUser
                    (
                            new OctetString(settings.get("username")),
                            new UsmUser
                                    (
                                            new OctetString(settings.get("username")),
                                            null,
                                            null,
                                            null,
                                            null
                                    )
                    );
        }
        else if(securityLevel.equals(AUTH_NO_PRIV))
        {
            snmp.getUSM().addUser
                    (
                            new OctetString(settings.get("username")),
                            new UsmUser
                                    (
                                            new OctetString(settings.get("username")),
                                            (settings.get("auth-protocol").toUpperCase().contains("SHA")) ? AuthSHA.ID : AuthMD5.ID,
                                            new OctetString(settings.get("password")),
                                            null,
                                            null
                                    )
                    );
        }
        else if(securityLevel.equals(AUTH_PRIV))
        {
            OID privProtocol = PrivAES256.ID;

            String strPrivProtocol = settings.get("priv-protocol");

            if (strPrivProtocol.toUpperCase().contains("3DES"))
                privProtocol = Priv3DES.ID;
            else if (strPrivProtocol.toUpperCase().contains("AES128"))
                privProtocol = PrivAES128.ID;
            else if (strPrivProtocol.toUpperCase().contains("AES192"))
                privProtocol = PrivAES192.ID;
            else if (strPrivProtocol.toUpperCase().contains("DES"))
                privProtocol = PrivDES.ID;

            snmp.getUSM().addUser
                    (
                            new OctetString(settings.get("username")),
                            new UsmUser
                                    (
                                            new OctetString(settings.get("username")),
                                            (settings.get("auth-protocol").contains("SHA")) ? AuthSHA.ID : AuthMD5.ID,
                                            new OctetString(settings.get("password")),
                                            privProtocol,
                                            new OctetString(settings.get("priv-protocol-password"))
                                    )
                    );
        }

        UserTarget usrTarget = new UserTarget();
        usrTarget.setVersion(SnmpConstants.version3);
        usrTarget.setAddress(new UdpAddress(host + '/' + port));
        usrTarget.setRetries(2);
        usrTarget.setSecurityLevel(Integer.valueOf(settings.get("security-level")));
        usrTarget.setSecurityName(new OctetString(settings.get("username")));
        usrTarget.setTimeout(5000);

        PDU pdu = new ScopedPDU();
        pdu.setType(PDU.NOTIFICATION);
        pdu.add(new VariableBinding(SnmpConstants.sysUpTime,  new OctetString(new Date().toString())));
        pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(TRAP_OID)));
        pdu.add(new VariableBinding(SnmpConstants.snmpTrapAddress, new IpAddress(trapHost)));

        for (Field field : snmpData.getClass().getDeclaredFields())
        {
            if(field.get(snmpData) != null) {
                try {
                    Object snmpVal = new OctetString(field.get(snmpData).toString());

                    if (!(snmpVal.equals(" ") || snmpVal.equals(""))) {
                        pdu.add(new VariableBinding(new OID(lookup.getOID(field.getName())), new OctetString(snmpVal.toString())));
                    }
                } catch (Throwable ex) {
                    logger.error("Error reading snmp data field:", ex);
                }
            }
        }

        snmp.send(pdu, usrTarget);
        snmp.close();
    }

    /**
     * Parses the config xml
     * @param 	xml			Configuration file locations
     * @return				Map<String, String> - Map of config objects
     * @throws 				DocumentException
     */
    private static Map<String, String> parseXML(String xml) throws DocumentException
    {
        Map<String, String> map = new HashMap<String, String>();
        SAXReader reader = new SAXReader();
        Document document = reader.read(xml);
        Element root = document.getRootElement();

        for (Iterator<Element> i = root.elementIterator(); i.hasNext();)
        {
            Element element = (Element) i.next();
            if (element.getName().equals("snmp-v3"))
            {
                Iterator<Element> elementIterator = element.elementIterator();
                for (Iterator<Element> j = elementIterator; j.hasNext();)
                {
                    element = (Element) j.next();
                    map.put(element.getName(), element.getText());
                }
            }
            else {
                map.put(element.getName(), element.getText());
            }
        }

        return map;
    }

    /**
     * Parses the command line arguments that are passed
     * @param 	args			Arguments passed to this project
     * @throws DataFormatException 	Unable to parse arguments
     */
    private static void parseArgs(String[] args) throws DataFormatException
    {
        try {

            if(bLogging){
                if(args != null){
                    logger.debug("CUSTOM ACTIONS ARGS :: " + Arrays.toString(args));
                  //  logger.debug("LOCAL ENGINE ID ::" + );
                }
            }

            if (args[0].equals("--help") || args[0].equals("--h") || args[0].equals("-h") || args[0].equals("-help"))
            {
                bLogging = false;
                System.out.println("Usage: java -jar SNMPTrapSender.jar -m <options>\n");

                System.out.println("Options:");
                System.out.println("\t-a\t-\tApplication Name");
                System.out.println("\t-trig\t-\tTriggered by");
                System.out.println("\t-n\t-\tNodes involved");
                System.out.println("\t-b\t-\tBusiness txns involved");
                System.out.println("\t-mac\t-\tMachines involved");
                System.out.println("\t-tier\t-\tTiers involved");
                System.out.println("\t-e\t-\tEvent Time");
                System.out.println("\t-sever\t-\tSeverity");
                System.out.println("\t-type\t-\tType");
                System.out.println("\t-summ\t-\tSummary");
                System.out.println("\t-link\t-\tLink");
                System.out.println("\t-tag\t-\tTag");
                return;
            }
            else if (args[0].equals("-m"))
            {
                bLogging = false;
                for (int i = 1; i < args.length - 1; i++)
                {
                    if (args[i].equals("-a")) {
                        APP_NAME = args[++i];
                    } else if (args[i].equals("-trig")) {
                        POLICY_NAME = args[++i];
                    } else if (args[i].equals("-n")) {
                        NODES = args[++i];
                    } else if (args[i].equals("-b")) {
                        BTs = args[++i];
                    } else if (args[i].equals("-mac")) {
                        MACHINES = args[++i];
                    } else if (args[i].equals("-tier")) {
                        TIERS = args[++i];
                    } else if (args[i].equals("-e")) {
                        PVN_ALERT_TIME = args[++i];
                    } else if (args[i].equals("-sever")) {
                        SEVERITY = args[++i];
                    } else if (args[i].equals("-type")) {
                        AFFECTED_ENTITY_TYPE = args[++i];
                    } else if (args[i].equals("-summ")) {
                        SUMMARY_MESSAGE = args[++i];
                    } else if (args[i].equals("-link")) {
                        DEEP_LINK_URL = args[++i];
                    } else if (args[i].equals("-tag")) {
                        TAG = args[++i];
                    }
                }
                return;
            }

            int param = 0;
            if (!isHRVEvent(args[args.length - 3])) {    //other events

                IS_HEALTH_RULE_VIOLATION = false;

                APP_NAME = args[param++];
                APP_ID = args[param++];
                EN_TIME = args[param++];
                PRIORITY = args[param++];
                SEVERITY = args[param++];
                TAG = args[param++];
                EN_NAME = args[param++];
                EN_ID = args[param++];
                EN_INTERVAL_IN_MINUTES = args[param++];
                NUMBER_OF_EVENT_TYPES = Integer.parseInt(args[param++]);

                if (bLogging)
                {
                    logger.info("------------PARSING------------");
                    logger.info("APP_NAME: " + APP_NAME);
                    logger.info("APP_ID: " + APP_ID);
                    logger.info("EN_TIME: " + EN_TIME);
                    logger.info("PRIORITY: " + PRIORITY);
                    logger.info("SEVERITY: " + SEVERITY);
                    logger.info("TAG: " + TAG);
                    logger.info("EN_NAME: " + EN_NAME);
                    logger.info("EN_ID: " + EN_ID);
                    logger.info("EN_INTERVAL_IN_MINUTES: " + EN_INTERVAL_IN_MINUTES);
                    logger.info("NUMBER_OF_EVENT_TYPES: " + NUMBER_OF_EVENT_TYPES);
                }

                event_types = new ArrayList<Event_Type>();
                for (int i = 0; i < NUMBER_OF_EVENT_TYPES; i++) {
                    Event_Type event_type = new Event_Type();
                    event_type.EVENT_TYPE = args[param++];
                    event_type.EVENT_TYPE_NUM = Integer.parseInt(args[param++]);
                    event_types.add(event_type);

                    if (bLogging)
                    {
                        logger.info("event_type.EVENT_TYPE: " + event_type.EVENT_TYPE);
                        logger.info("event_type.EVENT_TYPE_NUM: " + event_type.EVENT_TYPE_NUM);
                    }
                }

                NUMBER_OF_EVENT_SUMMARIES = Integer.parseInt(args[param++]);

                event_summaries = new ArrayList<Event_Summary>();
                for (int i = 0; i < NUMBER_OF_EVENT_SUMMARIES; i++) {
                    Event_Summary event_summary = new Event_Summary();
                    event_summary.EVENT_SUMMARY_ID = args[param++];
                    event_summary.EVENT_SUMMARY_TIME = args[param++];
                    event_summary.EVENT_SUMMARY_TYPE = args[param++];
                    event_summary.EVENT_SUMMARY_SEVERITY = args[param++];
                    event_summary.EVENT_SUMMARY_STRING = args[param++];
                    event_summaries.add(event_summary);

                    if (bLogging)
                    {
                        logger.info("event_summary.EVENT_SUMMARY_ID: " + event_summary.EVENT_SUMMARY_ID);
                        logger.info("event_summary.EVENT_SUMMARY_TIME: " + event_summary.EVENT_SUMMARY_TIME);
                        logger.info("event_summary.EVENT_SUMMARY_TYPE: " + event_summary.EVENT_SUMMARY_TYPE);
                        logger.info("event_summary.EVENT_SUMMARY_SEVERITY: " + event_summary.EVENT_SUMMARY_SEVERITY);
                        logger.info("event_summary.EVENT_SUMMARY_STRING: " + event_summary.EVENT_SUMMARY_STRING);
                    }
                }

                DEEP_LINK_URL = args[param] + EN_ID;

                if (bLogging)
                {
                    logger.info("DEEP_LINK_URL: " + DEEP_LINK_URL);
                    logger.info("_______________________________________");
                }

                // determine and set the OID for the notification
                setOID();

            } else {    // health rule violation

                IS_HEALTH_RULE_VIOLATION = true;

                List<String> ipAddresses = new ArrayList<String>();
                List<String> ipListTemp;
                String ip;

                RESTToolkit rtk = null;
                try {
                    rtk = new RESTToolkit(CONTROLLER_USERNAME, CONTROLLER_PASSWORD, "http://" + CONTROLLER_HOST + ":" + CONTROLLER_PORT, null);
                } catch (Throwable ex) {
                    rtk = null;
                    logger.error("Could not instaniate the RESTToolkit", ex);
                }


                APP_NAME = args[param++];											// 0
                APP_ID = args[param++];												// 1
                PVN_ALERT_TIME = args[param++];										// 2
                PRIORITY = args[param++];											// 3
                SEVERITY = args[param++];											// 4
                TAG = args[param++];												// 5
                POLICY_NAME = args[param++];										// 6
                POLICY_ID = args[param++];											// 7
                PVN_TIME_PERIOD_IN_MINUTES = args[param++];							// 8
                AFFECTED_ENTITY_TYPE = args[param++];								// 9
                AFFECTED_ENTITY_NAME = args[param++];								// 10
                AFFECTED_ENTITY_ID = args[param++];									// 11
                NUMBER_OF_EVALUATION_ENTITIES = Integer.parseInt(args[param++]);	// 12

                if (AFFECTED_ENTITY_TYPE != null) {
                    AFFECTED_ENTITY_TYPE = new String(AFFECTED_ENTITY_TYPE.trim());
                }
                if (AFFECTED_ENTITY_NAME != null) {
                    AFFECTED_ENTITY_NAME = new String(AFFECTED_ENTITY_NAME.trim());
                }
                if (AFFECTED_ENTITY_ID != null) {
                    AFFECTED_ENTITY_ID = new String(AFFECTED_ENTITY_ID.trim());
                }

                if (bLogging)
                {
                    logger.info("------------PARSING------------");
                    logger.info("APP_NAME: " + APP_NAME);
                    logger.info("APP_ID: " + APP_ID);
                    logger.info("PVN_ALERT_TIME: " + PVN_ALERT_TIME);
                    logger.info("PRIORITY: " + PRIORITY);
                    logger.info("SEVERITY: " + SEVERITY);
                    logger.info("TAG: " + TAG);
                    logger.info("POLICY_NAME: " + POLICY_NAME);
                    logger.info("POLICY_ID: " + POLICY_ID);
                    logger.info("PVN_TIME_PERIOD_IN_MINUTES: " + PVN_TIME_PERIOD_IN_MINUTES);
                    logger.info("AFFECTED_ENTITY_TYPE: " + AFFECTED_ENTITY_TYPE);
                    logger.info("AFFECTED_ENTITY_NAME: " + AFFECTED_ENTITY_NAME);
                    logger.info("AFFECTED_ENTITY_ID: " + AFFECTED_ENTITY_ID);
                    logger.info("NUMBER_OF_EVALUATION_ENTITIES: " + NUMBER_OF_EVALUATION_ENTITIES);
                }

                try{
                    if (AFFECTED_ENTITY_TYPE != null && AFFECTED_ENTITY_ID != null) {

                        if (AFFECTED_ENTITY_TYPE.equals("APPLICATION")) {
                            // get the IP Addresses for all nodes in the application
                            ipListTemp = rtk.getIPV4AddressesForApp(APP_NAME);
                            addIPV4Addresses(ipListTemp, ipAddresses);
                        } else  if (AFFECTED_ENTITY_TYPE.equals("APPLICATION_COMPONENT")) {
                            // get the IP Addresses for all nodes in the tier
                            ipListTemp = rtk.getIPV4AddressesForTier(APP_NAME, AFFECTED_ENTITY_ID);
                            addIPV4Addresses(ipListTemp, ipAddresses);
                        } else  if (AFFECTED_ENTITY_TYPE.equals("APPLICATION_COMPONENT_NODE")) {
                            // get the IP Address for the node
                            ip = rtk.getIPV4AddressForNode(APP_NAME, AFFECTED_ENTITY_ID);
                            addIPV4Address(ipAddresses, ip);
                        } else  if (AFFECTED_ENTITY_TYPE.equals("BUSINESS_TRANSACTION")) {
                            // get the IP Addresses for all nodes in the tier this BT belongs to
                            ipListTemp = rtk.getIPV4AddressesForBT(APP_NAME, AFFECTED_ENTITY_ID);
                            addIPV4Addresses(ipListTemp, ipAddresses);
                        }

                    }
                } catch (Throwable ex) {
                    logger.error("A problem occured utilizing the RESTToolkit", ex);
                }

                entities = new ArrayList<Evaluation_Entity>();
                for (int i = 0; i < NUMBER_OF_EVALUATION_ENTITIES; i++)
                {
                    Evaluation_Entity entity = new Evaluation_Entity();
                    entity.EVALUATION_ENTITY_TYPE = args[param++];
                    if (entity.EVALUATION_ENTITY_TYPE != null) {
                        entity.EVALUATION_ENTITY_TYPE = new String(entity.EVALUATION_ENTITY_TYPE.trim());
                    }

                    entity.EVALUATION_ENTITY_NAME = args[param++];
                    if (entity.EVALUATION_ENTITY_NAME != null) {
                        entity.EVALUATION_ENTITY_NAME = new String(entity.EVALUATION_ENTITY_NAME.trim());
                    }

                    entity.EVALUATION_ENTITY_ID = args[param++];
                    if (entity.EVALUATION_ENTITY_ID != null) {
                        entity.EVALUATION_ENTITY_ID = new String(entity.EVALUATION_ENTITY_ID.trim());
                    }

                    if (entity.EVALUATION_ENTITY_TYPE.contains("APPLICATION_COMPONENT_NODE")) {
                        NODES += entity.EVALUATION_ENTITY_NAME + " ";
                    } else if (entity.EVALUATION_ENTITY_TYPE.contains("APPLICATION_COMPONENT")) {
                        TIERS += entity.EVALUATION_ENTITY_NAME + " ";
                    } else if (entity.EVALUATION_ENTITY_TYPE.contains("MACHINE_INSTANCE")) {
                        MACHINES += entity.EVALUATION_ENTITY_NAME + " ";
                    } else if (entity.EVALUATION_ENTITY_TYPE.contains("BUSINESS_TRANSACTION")) {
                        BTs += entity.EVALUATION_ENTITY_NAME + " ";
                    } else if (AFFECTED_ENTITY_TYPE.contains("BUSINESS_TRANSACTION")) {
                        BTs += AFFECTED_ENTITY_NAME + " ";
                    }

                    try {

                        if (AFFECTED_ENTITY_TYPE != null && entity.EVALUATION_ENTITY_TYPE != null && entity.EVALUATION_ENTITY_ID != null) {

                            if (!AFFECTED_ENTITY_TYPE.equals("APPLICATION") &&
                                    !AFFECTED_ENTITY_TYPE.equals("APPLICATION_COMPONENT")  &&
                                    !AFFECTED_ENTITY_TYPE.equals("APPLICATION_COMPONENT_NODE") &&
                                    !AFFECTED_ENTITY_TYPE.equals("BUSINESS_TRANSACTION")) {

                                if (entity.EVALUATION_ENTITY_TYPE.equals("APPLICATION_COMPONENT")) {
                                    // get the IP Addresses for all nodes in the tier
                                    ipListTemp = rtk.getIPV4AddressesForTier(APP_NAME, entity.EVALUATION_ENTITY_ID);
                                    addIPV4Addresses(ipListTemp, ipAddresses);
                                } else  if (entity.EVALUATION_ENTITY_TYPE.equals("APPLICATION_COMPONENT_NODE")) {
                                    // get the IP Address for the node
                                    ip = rtk.getIPV4AddressForNode(APP_NAME, entity.EVALUATION_ENTITY_ID);
                                    addIPV4Address(ipAddresses, ip);
                                } else  if (entity.EVALUATION_ENTITY_TYPE.equals("BUSINESS_TRANSACTION")) {
                                    // get the IP Addresses for all nodes in the tier this BT belongs to
                                    ipListTemp = rtk.getIPV4AddressesForBT(APP_NAME, entity.EVALUATION_ENTITY_ID);
                                    addIPV4Addresses(ipListTemp, ipAddresses);
                                } else {
                                    // get the IP Addresses for all nodes in the application
                                    ipListTemp = rtk.getIPV4AddressesForApp(APP_NAME);
                                    addIPV4Addresses(ipListTemp, ipAddresses);
                                }

                            }

                        }

                    } catch (Throwable ex) {
                        logger.error("A problem occured utilizing the RESTToolkit", ex);
                    }

                    entity.NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY = Integer.parseInt(args[param++]);

                    if (bLogging)
                    {
                        logger.info("NODES: " + NODES);
                        logger.info("TIERS: " + TIERS);
                        logger.info("MACHINES: " + MACHINES);
                        logger.info("BTs: " + BTs);
                        logger.info("entity.EVALUATION_ENTITY_TYPE: " + entity.EVALUATION_ENTITY_TYPE);
                        logger.info("entity.EVALUATION_ENTITY_NAME: " + entity.EVALUATION_ENTITY_NAME);
                        logger.info("entity.EVALUATION_ENTITY_ID: " + entity.EVALUATION_ENTITY_ID);
                        logger.info("entity.NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY: " + entity.NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY);
                    }

                    entity.triggers = new ArrayList<Triggered_Condition>();
                    for (int j = 0; j < entity.NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY; j++)
                    {
                        Triggered_Condition trigger = new Triggered_Condition();
                        trigger.SCOPE_TYPE_x = args[param++];
                        trigger.SCOPE_NAME_x = args[param++];
                        trigger.SCOPE_ID_x = args[param++];
                        trigger.CONDITION_NAME_x = args[param++];
                        trigger.CONDITION_ID_x = args[param++];
                        trigger.OPERATOR_x = args[param++];
                        trigger.CONDITION_UNIT_TYPE_x = args[param++];

                        if (trigger.CONDITION_UNIT_TYPE_x.contains("BASELINE_"))
                        {
                            trigger.USE_DEFAULT_BASELINE_x = args[param++];
                            if(trigger.USE_DEFAULT_BASELINE_x.toLowerCase().equals("false")){
                                trigger.BASELINE_NAME_x = args[param++];
                                trigger.BASELINE_ID_x = args[param++];
                            }
                        }

                        trigger.THRESHOLD_VALUE_x = args[param++];
                        trigger.OBSERVED_VALUE_x = args[param++];

                        if (bLogging)
                        {
                            logger.info("trigger.SCOPE_TYPE_x: " + trigger.SCOPE_TYPE_x);
                            logger.info("trigger.SCOPE_NAME_x: " + trigger.SCOPE_NAME_x);
                            logger.info("trigger.SCOPE_ID_x: " + trigger.SCOPE_ID_x);
                            logger.info("trigger.CONDITION_NAME_x: " + trigger.CONDITION_NAME_x);
                            logger.info("trigger.CONDITION_ID_x: " + trigger.CONDITION_ID_x);
                            logger.info("trigger.OPERATOR_x: " + trigger.OPERATOR_x);
                            logger.info("trigger.CONDITION_UNIT_TYPE_x: " + trigger.CONDITION_UNIT_TYPE_x);
                            logger.info("trigger.USE_DEFAULT_BASELINE_x: " + trigger.USE_DEFAULT_BASELINE_x);
                            logger.info("trigger.BASELINE_NAME_x: " + trigger.BASELINE_NAME_x);
                            logger.info("trigger.BASELINE_NAME_x: " + trigger.BASELINE_NAME_x);
                            logger.info("trigger.THRESHOLD_VALUE_x: " + trigger.THRESHOLD_VALUE_x);
                            logger.info("trigger.OBSERVED_VALUE_x: " + trigger.OBSERVED_VALUE_x);
                        }

                        entity.triggers.add(trigger);
                    }
                    entities.add(entity);
                }

                SUMMARY_MESSAGE = args[param++];
                INCIDENT_ID = args[param++];
                DEEP_LINK_URL = args[param++] + INCIDENT_ID;
                HR_EVENT_TYPE = args[param++];


                // add IP Addresses here - IP_ADDRESSES = 10.125.21.2,10.125.21.3
                StringBuffer buff = new StringBuffer();
                if (ipAddresses.size() > 0) {

                    for (String str : ipAddresses) {
                        buff.append(str);
                        buff.append(",");
                    }
                    String str = buff.toString().trim();
                    IP_ADDRESSES = str.substring(0, str.length() - 1);

                } else {
                    IP_ADDRESSES = "null";
                }

                if (bLogging)
                {
                    logger.info("SUMMARY_MESSAGE: " + SUMMARY_MESSAGE);
                    logger.info("INCIDENT_ID: " + INCIDENT_ID);
                    logger.info("DEEP_LINK_URL: " + DEEP_LINK_URL);
                    logger.info("HR_EVENT_TYPE: " + HR_EVENT_TYPE);
                    logger.info("_______________________________________");
                }

                // determine and set the OID for the notification
                setOID();


            }

        }


        catch (Throwable e) {
            throw new DataFormatException(e.toString());
        }
    }

    /**
     * Discussed with Jon Reid from controller to figure out the right way of differentiating a HRV and non-HRV.
     * @param eventType
     * @return
     */
    private static boolean isHRVEvent(String eventType) {
        if(eventType != null){
            return eventType.startsWith("POLICY");
        }
        return false;
    }

    private static void addIPV4Address(List<String> ipList, String ip) {
        if (ip != null && (!ipList.contains(ip))) {
            ipList.add(ip);
        }
    }
    private static void addIPV4Addresses(List<String> source, List<String> destination) {
        if (source != null) {
            for (String ip : source) {
                if (!destination.contains(ip)) {
                    destination.add(ip);
                }
            }
        }
    }

    /**
     * Determines and sets the appropriate OID for the notification based on the value set
     * for the configuration option "mib-version".
     *
     */
    private static void setOID() {

        switch (MIB_VERSION) {
            case 1:
                TRAP_OID = TRAP_OID_01;
                break;

            case 2:
                if (HR_EVENT_TYPE.startsWith("POLICY_CLOSE") || HR_EVENT_TYPE.equals("POLICY_CANCELLED")) {
                    TRAP_OID = TRAP_OID_02;
                } else if (HR_EVENT_TYPE.equals("NON_POLICY_EVENT")) {
                    TRAP_OID = TRAP_OID_03;
                } else {
                    TRAP_OID = TRAP_OID_01;
                }
                break;

            case 3:
                if (HR_EVENT_TYPE.equals("POLICY_OPEN_WARNING")) {
                    TRAP_OID = TRAP_OID_01;
                } else if (HR_EVENT_TYPE.equals("POLICY_OPEN_CRITICAL")) {
                    TRAP_OID = TRAP_OID_02;
                } else if (HR_EVENT_TYPE.equals("POLICY_UPGRADED")) {
                    TRAP_OID = TRAP_OID_03;
                } else if (HR_EVENT_TYPE.equals("POLICY_DOWNGRADED")) {
                    TRAP_OID = TRAP_OID_04;
                } else if (HR_EVENT_TYPE.startsWith("POLICY_CLOSE")) {
                    TRAP_OID = TRAP_OID_05;
                } else if (HR_EVENT_TYPE.equals("POLICY_CANCELLED")) {
                    TRAP_OID = TRAP_OID_05;
                } else if (HR_EVENT_TYPE.equals("NON_POLICY_EVENT")) {
                    TRAP_OID = TRAP_OID_06;
                } else if(HR_EVENT_TYPE.equals("POLICY_CANCELLED_WARNING")) {
                    TRAP_OID = TRAP_OID_07;
                } else if(HR_EVENT_TYPE.equals("POLICY_CANCELLED_CRITICAL")) {
                    TRAP_OID = TRAP_OID_08;
                } else if(HR_EVENT_TYPE.equals("POLICY_CONTINUES_WARNING")) {
                    TRAP_OID = TRAP_OID_09;
                } else if(HR_EVENT_TYPE.equals("POLICY_CONTINUES_CRITICAL")) {
                    TRAP_OID = TRAP_OID_10;
                } else {
                    TRAP_OID = TRAP_OID_05;
                }
                break;

            default:
                TRAP_OID = TRAP_OID_01;
                break;
        }

    }

    /**
     * Removes double quotes from passed arguments
     * @param 	args	Passed arguments
     */
    private static void removeDoubleQuotes(String[] args)
    {
        for (int i=0; i < args.length; i++)
        {
            args[i]=args[i].replaceAll("\"", "");
        }
    }

    /**
     * Logs info level information
     */
    private static void logInfo(Object message) {
        if (bLogging)
        {
            logger.info(message);
        }
    }
}
