package com.appdynamics.extensions.snmp.config;

import java.util.Arrays;

public class Configuration {

    public static final int DEFAULT_MIB_VERSION = 1;
    public static final int DEFAULT_SNMP_VERSION = 3;

    private Receiver[] receivers;
    private String community;
    private String senderHost;
    private int mibVersion = DEFAULT_MIB_VERSION;
    private int snmpVersion = DEFAULT_SNMP_VERSION;
    private SnmpV3Configuration snmpV3Configuration;
    private String encryptionKey;
    private String accountName;
    private boolean isMultiTenant;
    private boolean fetchMachineInfoFromApi;
    private ControllerConfig controller;


    public Receiver[] getReceivers() {
        return receivers;
    }

    public void setReceivers(Receiver[] receivers) {
        this.receivers = receivers;
    }

    public String getCommunity() {
        return community;
    }

    public void setCommunity(String community) {
        this.community = community;
    }

    public String getSenderHost() {
        return senderHost;
    }

    public void setSenderHost(String senderHost) {
        this.senderHost = senderHost;
    }

    public int getMibVersion() {
        return mibVersion;
    }

    public void setMibVersion(int mibVersion) {
        this.mibVersion = mibVersion;
    }

    public int getSnmpVersion() {
        return snmpVersion;
    }

    public void setSnmpVersion(int snmpVersion) {
        this.snmpVersion = snmpVersion;
    }

    public SnmpV3Configuration getSnmpV3Configuration() {
        return snmpV3Configuration;
    }

    public void setSnmpV3Configuration(SnmpV3Configuration snmpV3Configuration) {
        this.snmpV3Configuration = snmpV3Configuration;
    }

    public String getAccountName() {
        return accountName;
    }

    public void setAccountName(String accountName) {
        this.accountName = accountName;
    }

    public boolean getIsMultiTenant() {
        return isMultiTenant;
    }

    public void setIsMultiTenant(boolean isMultiTenant) {
        this.isMultiTenant = isMultiTenant;
    }

    public String getEncryptionKey() {
        return encryptionKey;
    }

    public void setEncryptionKey(String encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public ControllerConfig getController() {
        return controller;
    }

    public void setController(ControllerConfig controller) {
        this.controller = controller;
    }

    public boolean isFetchMachineInfoFromApi() {
        return fetchMachineInfoFromApi;
    }

    public void setFetchMachineInfoFromApi(boolean fetchMachineInfoFromApi) {
        this.fetchMachineInfoFromApi = fetchMachineInfoFromApi;
    }

    @Override
    public String toString() {
        return "Configuration{" +
                "receivers=" + Arrays.toString(receivers) +
                ", community='" + community + '\'' +
                ", senderHost='" + senderHost + '\'' +
                ", mibVersion=" + mibVersion +
                ", snmpVersion=" + snmpVersion +
                ", snmpV3Configuration=" + snmpV3Configuration +
                ", controller=" + controller +
                '}';
    }
}
