package com.appdynamics.extensions.snmp.api;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "business-transactions")
public class BusinessTransactionWrapper {

    @XmlElement(name="business-transaction")
    private List<BusinessTransaction> businessTransactions;

    public List<BusinessTransaction> getBusinessTransactions() {
        return businessTransactions;
    }

    public void setBusinessTransactions(List<BusinessTransaction> businessTransactions) {
        this.businessTransactions = businessTransactions;
    }
}
