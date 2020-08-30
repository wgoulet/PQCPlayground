package com.example.servingwebcontent.demo;

import java.util.Objects;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.PrePersist;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

@Entity
public class Democertificate {
    private @Id @GeneratedValue Long id;
    private static Log log = LogFactory.getLog(Democertificate.class);
    private String certName;
    private String certSubjectDN;
    private String certASN1;

    private Democertificate() {
    }

    public Democertificate(String certName, String certSubjectDN) {
        this.certName = certName;
        this.certSubjectDN = certSubjectDN;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if ((o == null) || getClass() != o.getClass())
            return false;
        Democertificate cert = (Democertificate) o;
        return Objects.equals(id, cert.id) && Objects.equals(certName, cert.certName)
                && Objects.equals(certSubjectDN, cert.certSubjectDN);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, certName, certSubjectDN);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getCertName() {
        return certName;
    }

    public void setCertName(String certName) {
        this.certName = certName;
    }

    public String getCertSubjectDN() {
        return this.certSubjectDN;
    }

    public void setCertSubjectDN(String certSubjectDN) {
        this.certSubjectDN = certSubjectDN;
    }

    public void setCertASN1(String asn1String) {
        this.certASN1 = asn1String;
    }

    public String getCertASN1() {
        return this.certASN1;
    }

    @PrePersist
    public void generateCertASN() {
        this.certSubjectDN = this.certSubjectDN + ",C=US";
        log.info(String.format("About to persist data %s",this.certSubjectDN));
    }

    @Override
    public String toString()
    {
        return String.format("Certificate information: name %s subjectDN %s id %o", this.certName,this.certSubjectDN,this.id);
    }
}