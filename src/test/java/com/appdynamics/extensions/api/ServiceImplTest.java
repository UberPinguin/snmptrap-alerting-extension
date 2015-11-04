package com.appdynamics.extensions.api;


import com.appdynamics.extensions.snmp.api.*;
import com.appdynamics.extensions.snmp.config.ControllerConfig;
import junit.framework.Assert;
import org.junit.Test;

import java.util.List;

public class ServiceImplTest {

    IService service = new ServiceImpl();

    /*@Test
    public void testForValidBTEndpointCall(){
        ControllerConfig controller = new ControllerConfig();
        controller.setUseSsl(false);
        controller.setHost("mywindows.sandbox.appdynamics.com");
        controller.setPort(8090);
        controller.setUserAccount("kunal@customer1");
        controller.setPassword("appdynamics");

        ServiceBuilder serviceBuilder = new ServiceBuilder(true,controller.getUserAccount(),controller.getPassword(),controller.getConnectTimeoutInSeconds()*1000,controller.getSocketTimeoutInSeconds()*1000);
        EndpointBuilder endpointBuilder = new EndpointBuilder();
        String endpoint = endpointBuilder.buildBTsEndpoint(controller,13);
        List<BusinessTransaction> bts = service.getBTs(serviceBuilder,endpoint);
        Assert.assertNotNull(bts);

    }*/
}
