package com.example.servingwebcontent.demo;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Objects;
import java.io.StringWriter;
import java.math.BigInteger;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.PrePersist;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509v1CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyPairGenerator;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.lms.HSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.HSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mceliece.McElieceParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.data.annotation.Transient;

@Entity
public class Democertificate {
    private @Id @GeneratedValue Long id;
    private static Log log = LogFactory.getLog(Democertificate.class);
    private String certName;
    private String certSubjectDN;
    @Column (length = 10000)
    private String certASN1;
    @Column (length = 10000)
    private String certPrivateKey;
    transient private AsymmetricKeyParameter pubkey;
    transient private AsymmetricKeyParameter privkey;

    public Democertificate() {
       
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

    public void setCertPrivateKey(String privateKey) {
        this.certPrivateKey = privateKey;
    }

    public String getCertPrivateKey() {
        return this.certPrivateKey;
    }

    @PrePersist
    public void generateCertASN() {
         // https://github.com/bcgit/bc-java/blob/eb4b535f39048c6b0e2c9c14fd18b376453a63eb/pkix/src/test/java/org/bouncycastle/cert/test/BcCertTest.java#L525
        SecureRandom rand = new SecureRandom();
        RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(BigInteger.valueOf(0x1001), rand, 2048, 25);
        RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();
        rkpg.init(params);
        AsymmetricCipherKeyPair keypair = rkpg.generateKeyPair();
        pubkey = keypair.getPublic();
        privkey = keypair.getPrivate();
        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
        HashMap<String,String> certDN = Utilities.parseCertSubjectDN(this.certSubjectDN);
        log.info(String.format("About to persist data %s",this.certSubjectDN));
        X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);
        builder.addRDN(RFC4519Style.cn, certDN.get("CN"));
        builder.addRDN(RFC4519Style.o, certDN.get("O"));
        builder.addRDN(RFC4519Style.l, certDN.get("L"));
        builder.addRDN(RFC4519Style.st, certDN.get("ST"));
        builder.addRDN(RFC4519Style.c, certDN.get("C"));

        // Generate PQC keypair from
        // The Viability of Post-Quantum X.509 Certificates Panos Kampanakis, Peter Panburana, Ellie Daw1 and Daniel Van Geest2

        LMSParameters lparams = new LMSParameters(LMSigParameters.lms_sha256_n32_h10,LMOtsParameters.sha256_n32_w1);
        LMSParameters[] lmsParameters = {lparams};
        HSSKeyGenerationParameters pqcparams = new HSSKeyGenerationParameters(lmsParameters,rand);
        HSSKeyPairGenerator pqcgen = new HSSKeyPairGenerator();
        pqcgen.init(pqcparams);
        AsymmetricCipherKeyPair pqckeys = pqcgen.generateKeyPair();
        HSSPrivateKeyParameters pqcprivkey = (HSSPrivateKeyParameters) pqckeys.getPrivate();

        AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA256WithRSAEncryption");
        try{
            // Encode PQC key for embedding in cert along with signature
            PrivateKeyInfo pqcprivkeyinfo = org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory.createPrivateKeyInfo(pqcprivkey);
            ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlg, digAlgFinder.find(sigAlg)).build(this.privkey);
            X509v3CertificateBuilder certGen = new BcX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000),builder.build(), this.pubkey);

            X509CertificateHolder certH = certGen.build(sigGen);
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certH);
            StringWriter sw = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
            pemWriter.writeObject(cert);
            pemWriter.flush();
            this.certASN1 = sw.toString();
            log.info(sw.toString());
            PrivateKeyInfo privkeyinfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privkey);
            sw.close();
            sw = new StringWriter();
            pemWriter = new JcaPEMWriter(sw);
            pemWriter.writeObject(privkeyinfo);
            pemWriter.flush();
            this.certPrivateKey = sw.toString();
            log.info(sw.toString());
            sw.close();
            sw = new StringWriter();
            pemWriter = new JcaPEMWriter(sw);
            pemWriter.writeObject(pqcprivkeyinfo);
            pemWriter.flush();
            log.info(sw.toString());
            sw.close();
        
        } catch(Exception e)
        {
            log.info("Got exception" + e.getMessage());
        }
    }

    @Override
    public String toString()
    {
        return String.format("Certificate information: name %s subjectDN %s id %o", this.certName,this.certSubjectDN,this.id);
    }
}