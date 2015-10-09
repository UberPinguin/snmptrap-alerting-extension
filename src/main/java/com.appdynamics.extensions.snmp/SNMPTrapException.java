package com.appdynamics.extensions.snmp;


public class SNMPTrapException extends RuntimeException{
    public SNMPTrapException(String message, Throwable cause) {
        super(message, cause);
    }

    public SNMPTrapException(String message) {
        super(message);
    }
}
