package com.example.servingwebcontent.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DatabaseLoader implements CommandLineRunner {
    private final DemoCertificateRepository repository;

    @Autowired
    public DatabaseLoader(DemoCertificateRepository repository) {
        this.repository = repository;
    }

    @Override
    public void run (String...strings) throws Exception {
        this.repository.save(new DemoCertificate("firstcert","CN=firstcert,O=demo,C=US,L=Chicago,ST=IL"));
    }
    
}