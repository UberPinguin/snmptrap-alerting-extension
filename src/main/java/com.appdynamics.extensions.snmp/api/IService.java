package com.appdynamics.extensions.snmp.api;



import java.util.List;

/**
 * Interface for AppD Controller Rest APIs
 */
public interface IService {

    List<BusinessTransaction> getBTs(HttpClientBuilder httpClientBuilder, String endpoint) throws ServiceException;

    List<Node> getNodes(HttpClientBuilder httpClientBuilder, String endpoint) throws ServiceException;

}
