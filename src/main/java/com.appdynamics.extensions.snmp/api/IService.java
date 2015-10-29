package com.appdynamics.extensions.snmp.api;



import java.util.List;

/**
 * Interface for AppD Controller Rest APIs
 */
public interface IService {

    List<BusinessTransaction> getBTs(ServiceBuilder serviceBuilder, String endpoint) throws ServiceException;

}
