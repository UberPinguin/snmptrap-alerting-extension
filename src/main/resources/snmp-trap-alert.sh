#!/bin/sh

java -Dlog4j.configuration=file:conf/log4j.xml -DappDynamics.controller.multiTenant=false -jar snmp-trap-alert.jar "$@" &
