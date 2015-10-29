package com.appdynamics.extensions.snmp.config;


public class ControllerConfig {

    private String host;
    private int port;
    private String userAccount;
    private String password;
    private String encryptedPassword;
    private boolean useSsl;
    private int connectTimeoutInSeconds = 10;
    private int socketTimeoutInSeconds = 10;

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getUserAccount() {
        return userAccount;
    }

    public void setUserAccount(String userAccount) {
        this.userAccount = userAccount;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public boolean isUseSsl() {
        return useSsl;
    }

    public void setUseSsl(boolean useSsl) {
        this.useSsl = useSsl;
    }

    public int getConnectTimeoutInSeconds() {
        return connectTimeoutInSeconds;
    }

    public void setConnectTimeoutInSeconds(int connectTimeoutInSeconds) {
        this.connectTimeoutInSeconds = connectTimeoutInSeconds;
    }

    public int getSocketTimeoutInSeconds() {
        return socketTimeoutInSeconds;
    }

    public void setSocketTimeoutInSeconds(int socketTimeoutInSeconds) {
        this.socketTimeoutInSeconds = socketTimeoutInSeconds;
    }

    @Override
    public String toString() {
        return "Controller{" +
                "host='" + host + '\'' +
                ", port=" + port +
                ", userAccount='" + userAccount + '\'' +
                ", encryptedPassword='" + encryptedPassword + '\'' +
                ", useSsl=" + useSsl +
                ", connectTimeoutInSeconds='" + connectTimeoutInSeconds + '\'' +
                ", socketTimeoutInSeconds='" + socketTimeoutInSeconds + '\'' +
                '}';
    }
}
