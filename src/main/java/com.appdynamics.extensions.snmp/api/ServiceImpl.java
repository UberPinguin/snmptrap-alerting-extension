package com.appdynamics.extensions.snmp.api;


import com.appdynamics.extensions.http.Response;
import com.appdynamics.extensions.http.SimpleHttpClient;
import com.google.common.collect.Lists;
import org.apache.log4j.Logger;

import java.net.HttpURLConnection;
import java.util.List;

public class ServiceImpl implements IService {

    private static Logger logger = Logger.getLogger(ServiceImpl.class);

    @Override
    public List<BusinessTransaction> getBTs(HttpClientBuilder httpClientBuilder, String endpoint) throws ServiceException {
        logger.debug("getBTs :: building http client");
        SimpleHttpClient simpleHttpClient = null;
        try {
            simpleHttpClient = httpClientBuilder.buildHttpClient(BusinessTransactionWrapper.class);
            logger.debug("getBTs :: target url" + endpoint);
            Response response = simpleHttpClient.target(endpoint).get();
            BusinessTransactionWrapper btWrapper = null;
            if (response != null && response.getStatus() == HttpURLConnection.HTTP_OK) {
                btWrapper = response.xml(BusinessTransactionWrapper.class);
                if (btWrapper != null && btWrapper.getBusinessTransactions()!= null) {
                    logger.debug("getBTs :: returning successfully");
                    return btWrapper.getBusinessTransactions();
                }
            }
        }
        catch(Exception e){
            String msg = "getBTs :: unable to get applications for " + endpoint;
            logger.error(msg,e);
            throw new ServiceException(msg,e);
        }
        finally{
            simpleHttpClient.close();
        }
        return Lists.newArrayList();
    }

    @Override
    public List<Node> getNodes(HttpClientBuilder httpClientBuilder, String endpoint) throws ServiceException {
        logger.debug("getNodes :: building http client");
        SimpleHttpClient simpleHttpClient = null;
        try {
            simpleHttpClient = httpClientBuilder.buildHttpClient(NodeWrapper.class);
            logger.debug("getNodes :: target url" + endpoint);
            Response response = simpleHttpClient.target(endpoint).get();
            NodeWrapper nodeWrapper = null;
            if (response != null && response.getStatus() == HttpURLConnection.HTTP_OK) {
                nodeWrapper = response.xml(NodeWrapper.class);
                if (nodeWrapper != null && nodeWrapper.getNodes()!= null) {
                    logger.debug("getNodes :: returning successfully");
                    return nodeWrapper.getNodes();
                }
            }
        }
        catch(Exception e){
            String msg = "getNodes :: unable to get nodes for " + endpoint;
            logger.error(msg,e);
            throw new ServiceException(msg,e);
        }
        finally{
            simpleHttpClient.close();
        }
        return Lists.newArrayList();
    }



   /* @Override
    public List<Application> getApplications(ServiceBuilder serviceBuilder,String endpoint) throws ServiceException{
        logger.debug("getApplications :: building http client");
        try {
            SimpleHttpClient simpleHttpClient = serviceBuilder.buildHttpClient(ApplicationWrapper.class);
            logger.debug("getApplications :: target url" + endpoint);
            Response response = simpleHttpClient.target(endpoint).get();
            ApplicationWrapper applicationWrapper = null;
            if (response != null && response.getStatus() == HttpURLConnection.HTTP_OK) {
                applicationWrapper = response.xml(ApplicationWrapper.class);
                if (applicationWrapper != null && applicationWrapper.getApplications() != null) {
                    logger.debug("getApplications :: returning successfully");
                    return applicationWrapper.getApplications();
                }
            }
        }
        catch(Exception e){
            String msg = "getApplications :: unable to get applications for " + endpoint;
            logger.error(msg,e);
            throw new ServiceException(msg,e);
        }
        return Lists.newArrayList();
    }

    @Override
    public List<PolicyViolation> getHealthRuleViolations(ServiceBuilder serviceBuilder, String endpoint) throws ServiceException{
        logger.debug("getHealthRuleViolations :: building http client");
        try {
            SimpleHttpClient simpleHttpClient = serviceBuilder.buildHttpClient(PolicyViolationWrapper.class);
            logger.debug("getHealthRuleViolations :: target url" + endpoint);
            Response response = simpleHttpClient.target(endpoint).get();
            PolicyViolationWrapper violationWrapper = null;
            if (response != null && response.getStatus() == HttpURLConnection.HTTP_OK) {
                violationWrapper = response.xml(PolicyViolationWrapper.class);
                if (violationWrapper != null && violationWrapper.getPolicyViolations() != null) {
                    logger.debug("getHealthRuleViolations :: returning successfully");
                    return violationWrapper.getPolicyViolations();
                }
            }
        }
        catch(Exception e){
            String msg = "getHealthRuleViolations :: unable to get applications for " + endpoint;
            logger.error(msg,e);
            throw new ServiceException(msg,e);
        }
        return Lists.newArrayList();
    }

    @Override
    public List<Event> getEvents(ServiceBuilder serviceBuilder,String endpoint) throws ServiceException{
        logger.debug("getEvents :: building http client");
        try {
            SimpleHttpClient simpleHttpClient = serviceBuilder.buildHttpClient(EventWrapper.class);
            logger.debug("getEvents :: target url" + endpoint);
            Response response = simpleHttpClient.target(endpoint).get();
            EventWrapper eventWrapper = null;
            if (response != null && response.getStatus() == HttpURLConnection.HTTP_OK) {
                eventWrapper = response.xml(EventWrapper.class);
                if (eventWrapper != null && eventWrapper.getEvents() != null) {
                    logger.debug("getEvents :: returning successfully");
                    return eventWrapper.getEvents();
                }
            }
        }
        catch(Exception e){
            String msg = "getEvents :: unable to get applications for " + endpoint;
            logger.error(msg,e);
            throw new ServiceException(msg,e);
        }
        return Lists.newArrayList();
    }*/

}
