package com.appdynamics.extensions.api;

import com.appdynamics.extensions.snmp.api.Node;
import com.appdynamics.extensions.snmp.api.NodeWrapper;
import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
import org.junit.Assert;
import org.junit.Test;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.util.Arrays;
import java.util.List;

public class ServiceImplTest {

    public static final Joiner JOIN_ON_COMMA = Joiner.on(",");


    @Test
    public void testNodesUnmarshalling() throws JAXBException {
        JAXBContext jc = JAXBContext.newInstance(NodeWrapper.class);
        Unmarshaller unmarshaller = jc.createUnmarshaller();
        NodeWrapper nodeWrapper = (NodeWrapper) unmarshaller.unmarshal(this.getClass().getResourceAsStream("/nodes.xml"));
        org.junit.Assert.assertNotNull(nodeWrapper != null);
        org.junit.Assert.assertNotNull(nodeWrapper.getNodes().get(0) != null);
        //System.out.println("RESULT:" +   nodeWrapper.getNodes().get(0).getIpAddresses());
        org.junit.Assert.assertTrue(nodeWrapper.getNodes().get(0).getIpAddresses().get(0).equals("10.111.176.170"));
    }


    @Test
    public void testTransform(){
        Node node1 = new Node();
        String IP1 = "12.12.12.12";
        String IP2 = "43.54.23.12";
        node1.setIpAddresses(Arrays.asList(IP1, IP2));
        Node node2 = new Node();
        String IP3 = "11.11.11.11";
        String IP4 = "53.44.43.22";
        node2.setIpAddresses(Arrays.asList(IP3, IP4));
        List<String> ips = getIPAddresses(Arrays.asList(node1,node2));
        Assert.assertTrue(ips.contains(IP1 + "," + IP2));
        Assert.assertTrue(ips.contains(IP3 + "," + IP4));

    }

    private List<String> getIPAddresses(List<Node> allNodes) {
        Function<Node,String> ipAddressFunc = new Function<Node, String>() {
            @Override
            public String apply(Node input) {
                if(input.getIpAddresses() != null) {
                    return JOIN_ON_COMMA.join(input.getIpAddresses());
                }
                return "";
            }
        };
        return Lists.transform(allNodes, ipAddressFunc);
    }


}
