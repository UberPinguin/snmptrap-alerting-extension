package com.appdynamics.extensions.snmp.config;


public class SnmpV3Configuration {

    private int securityLevel;
    private String username;
    private String password;
    private String encryptedPassword;
    private String authProtocol;
    private String privProtocol;
    private String privProtocolPassword;
    private String encryptedPrivProtocolPassword;

    public int getSecurityLevel() {
        return securityLevel;
    }

    public void setSecurityLevel(int securityLevel) {
        this.securityLevel = securityLevel;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAuthProtocol() {
        return authProtocol;
    }

    public void setAuthProtocol(String authProtocol) {
        this.authProtocol = authProtocol;
    }

    public String getPrivProtocol() {
        return privProtocol;
    }

    public void setPrivProtocol(String privProtocol) {
        this.privProtocol = privProtocol;
    }

    public String getPrivProtocolPassword() {
        return privProtocolPassword;
    }

    public void setPrivProtocolPassword(String privProtocolPassword) {
        this.privProtocolPassword = privProtocolPassword;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public String getEncryptedPrivProtocolPassword() {
        return encryptedPrivProtocolPassword;
    }

    public void setEncryptedPrivProtocolPassword(String encryptedPrivProtocolPassword) {
        this.encryptedPrivProtocolPassword = encryptedPrivProtocolPassword;
    }

    @Override
    public String toString() {
        return "SnmpV3Configuration{" +
                "securityLevel=" + securityLevel +
                ", username='" + username + '\'' +
                ", encryptedPassword='" + encryptedPassword + '\'' +
                ", authProtocol='" + authProtocol + '\'' +
                ", privProtocol='" + privProtocol + '\'' +
                ", encryptedPrivProtocolPassword='" + encryptedPrivProtocolPassword + '\'' +
                '}';
    }
}
