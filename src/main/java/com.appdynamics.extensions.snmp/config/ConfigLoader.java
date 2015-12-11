package com.appdynamics.extensions.snmp.config;


import com.appdynamics.TaskInputArgs;
import com.appdynamics.extensions.crypto.CryptoUtil;
import com.appdynamics.extensions.yml.YmlReader;
import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import org.apache.log4j.Logger;

import java.io.File;
import java.util.Map;

public class ConfigLoader {

    public static final String TRAP_SENDER_HOME = "SNMP_TRAP_SENDER_HOME";
    public static final String CONFIG_FILENAME =  "config.yaml";
    public static final String SINGLE_TENANT_CONFIG_DIR = "conf" + File.separator;
    public static final String MULTI_TENANT_CONFIG_DIR = "conf" + File.separator + "accounts" + File.separator;
    public static final String SNMP_ENGINE_PROPERTIES = "snmp_engine.properties";
    private static Logger logger = Logger.getLogger(ConfigLoader.class);

    public static Configuration getConfig(boolean isMultiTenant, String accountId){
        String configDir = getConfigDir(isMultiTenant,accountId);
        String trapSenderHome = getTrapSenderHome();
        String configFile = trapSenderHome + configDir + CONFIG_FILENAME;
        Configuration config = YmlReader.readFromFile(configFile, Configuration.class);
        config.setIsMultiTenant(isMultiTenant);
        config.setAccountName(accountId);
        if(validateEncryptionFields(config)) {
            decryptPasswords(config);
        }
        return config;
    }

    private static boolean validateEncryptionFields(Configuration config) {
        if (!Strings.isNullOrEmpty(config.getEncryptionKey())) {
            return true;
        }
        return false;
    }

    private static void decryptPasswords(Configuration config) {
        if(config.getController() != null && !Strings.isNullOrEmpty(config.getController().getEncryptedPassword())){
            Map<String,String> taskArgs = createTaskArgs(config.getEncryptionKey(),config.getController().getEncryptedPassword());
            config.getController().setPassword(CryptoUtil.getPassword(taskArgs));
        }
        if(config.getSnmpV3Configuration() != null) {
            if (!Strings.isNullOrEmpty(config.getSnmpV3Configuration().getEncryptedPassword())) {
                Map<String, String> taskArgs = createTaskArgs(config.getEncryptionKey(), config.getSnmpV3Configuration().getEncryptedPassword());
                config.getSnmpV3Configuration().setPassword(CryptoUtil.getPassword(taskArgs));
            }
            if (!Strings.isNullOrEmpty(config.getSnmpV3Configuration().getEncryptedPrivProtocolPassword())) {
                Map<String, String> taskArgs = createTaskArgs(config.getEncryptionKey(), config.getSnmpV3Configuration().getEncryptedPrivProtocolPassword());
                config.getSnmpV3Configuration().setPrivProtocolPassword(CryptoUtil.getPassword(taskArgs));
            }
        }
    }

    private static Map<String,String> createTaskArgs(String encryptionKey, String password) {
        Map<String,String> taskArgs = Maps.newHashMap();
        taskArgs.put(TaskInputArgs.ENCRYPTION_KEY, encryptionKey);
        taskArgs.put(TaskInputArgs.PASSWORD_ENCRYPTED, password);
        return taskArgs;
    }

    public static String getTrapSenderHome() {
        return System.getProperty(TRAP_SENDER_HOME,"");
    }

    public static String getConfigDir(boolean isMultiTenant, String accountName) {
        if(isMultiTenant){
            return MULTI_TENANT_CONFIG_DIR + accountName + File.separator;
        }
        else{
            return SINGLE_TENANT_CONFIG_DIR;
        }
    }


    public static String getEngineConfig(boolean isMultiTenant, String accountName) {
        String configDir = ConfigLoader.getConfigDir(isMultiTenant, accountName);
        String enginePropFile = configDir + SNMP_ENGINE_PROPERTIES;
        String trapSenderHome = getTrapSenderHome();
        return trapSenderHome + enginePropFile;
    }

}
