package com.example.servingwebcontent.demo;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
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
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.util.ASN1Dump;
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
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
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
import org.bouncycastle.crypto.signers.RSADigestSigner;
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
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowSigner;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PrivateKey;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PublicKey;
import org.bouncycastle.pqc.jcajce.provider.rainbow.BCRainbowPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.rainbow.BCRainbowPublicKey;
import org.bouncycastle.pqc.jcajce.provider.rainbow.SignatureSpi.withSha512;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.RainbowPrivateKey;
import org.bouncycastle.pqc.crypto.lms.HSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.HSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2Parameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mceliece.McElieceParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.data.annotation.Transient;

@Entity
public class Democertificate {
    private @Id @GeneratedValue Long id;
    private static Log log = LogFactory.getLog(Democertificate.class);
    private String certName;
    private String certSubjectDN;
    @Column(length = 500000)
    private String certASN1;
    @Column(length = 500000)
    private String certPrivateKey;
    @Column(length = 500000)
    private String certPqcPrivateKey;
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

    public void setCertPqcPrivateKey(String privateKey) {
        this.certPqcPrivateKey = privateKey;
    }

    public String getCertPqcPrivateKey() {
        return this.certPqcPrivateKey;
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
        HashMap<String, String> certDN = Utilities.parseCertSubjectDN(this.certSubjectDN);
        log.info(String.format("About to persist data %s", this.certSubjectDN));
        X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);
        builder.addRDN(RFC4519Style.cn, certDN.get("CN"));
        builder.addRDN(RFC4519Style.o, certDN.get("O"));
        builder.addRDN(RFC4519Style.l, certDN.get("L"));
        builder.addRDN(RFC4519Style.st, certDN.get("ST"));
        builder.addRDN(RFC4519Style.c, certDN.get("C"));

        // Generate PQC keypair from
        // The Viability of Post-Quantum X.509 Certificates Panos Kampanakis, Peter
        // Panburana, Ellie Daw1 and Daniel Van Geest2

        RainbowParameters rparams = new RainbowParameters();
        RainbowKeyGenerationParameters rkeyparams = new RainbowKeyGenerationParameters(rand,rparams);
        RainbowKeyPairGenerator pqcgen = new RainbowKeyPairGenerator();
        pqcgen.init(rkeyparams);
        AsymmetricCipherKeyPair pqckeys = pqcgen.generateKeyPair();
        RainbowPrivateKeyParameters pqcprivkey = (RainbowPrivateKeyParameters) pqckeys.getPrivate();
        RainbowPublicKeyParameters pqcpubkey = (RainbowPublicKeyParameters) pqckeys.getPublic();
        BCRainbowPublicKey bpubkey = new BCRainbowPublicKey(pqcpubkey);

        AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA256WithRSAEncryption");
        try{
            ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlg, digAlgFinder.find(sigAlg)).build(this.privkey);
            RainbowSigner pqcsigner = new RainbowSigner();
            PQX509v3CertificateBuilder certGen = new PQX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000),builder.build(), this.pubkey,pqcpubkey);
            // Encode PQC key for embedding in cert along with signature
            // Unsure if this extension is understood to contain the encoded public key
            certGen.addExtension(PQCObjectIdentifiers.rainbow, false, bpubkey.getEncoded());
            X509CertificateHolder certH = certGen.build(sigGen,pqcsigner,pqcprivkey);
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certH);
            int len = cert.getEncoded().length;
            // Test out this flow with RSA; construct the signature using the same sequence of calls
            // we'll be using with Rainbow
            byte[] crsasig = cert.getSignature();
            String crsasigstr = "";
            for(byte c: crsasig)
            {
                byte[] ib = new byte[1];
                ib[0] = c;
                BigInteger bi = new BigInteger(1,ib);
                crsasigstr = crsasigstr + ":" + bi.toString(16);
            }
            log.info(crsasigstr);
            RSADigestSigner rsig = new RSADigestSigner(new SHA256Digest());
            rsig.init(true, (RSAKeyParameters)privkey);
            rsig.update(cert.getEncoded(),0,len);
            byte[] rsasig = rsig.generateSignature();
            String rsasigstr = "";
            for(byte b : rsasig)
            {
                byte[] ib = new byte[1];
                ib[0] = b;
                BigInteger bi = new BigInteger(1,ib);
                rsasigstr = rsasigstr + ":" + bi.toString(16);
            }
            log.info(rsasigstr);
            /* certGen.addExtension(ISOIECObjectIdentifiers.id_kem_rsa, false, rsasig);
             Generate a SHA256 hash of the certificate before passing it to the Rainbow signer
            SHA512Digest sha512Digest = new SHA512Digest();
            sha512Digest.update(cert.getEncoded(),0,len);
            byte[] digest = new byte[sha512Digest.getDigestSize()];
            sha512Digest.doFinal(digest, 0);
            // Sign the certificate with the pqc private key
            pqcsigner.init(true,pqcprivkey);
            byte[] pqcsig = pqcsigner.generateSignature(digest);
            // Add the signature to the certificate
            certGen.addExtension(PQCObjectIdentifiers.rainbowWithSha512, false, pqcsig);
            certH = certGen.build(sigGen,pqcsigner,pqcprivkey);
            cert = new JcaX509CertificateConverter().getCertificate(certH);
            log.info(ASN1Dump.dumpAsString(cert));
            */
            StringWriter sw = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
            pemWriter.writeObject(cert);
            pemWriter.flush();
            this.certASN1 = sw.toString();
            log.info(this.certASN1);
            PrivateKeyInfo privkeyinfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privkey);
            sw.close();
            sw = new StringWriter();
            pemWriter = new JcaPEMWriter(sw);
            pemWriter.writeObject(privkeyinfo);
            pemWriter.flush();
            this.certPrivateKey = sw.toString();
            log.info(sw.toString());
            sw.close();
            // Save the PQC private key
            RainbowPrivateKey pqcprivkeyinfo = new RainbowPrivateKey(pqcprivkey.getInvA1(),pqcprivkey.getB1(),
                pqcprivkey.getInvA2(),pqcprivkey.getB2(),pqcprivkey.getVi(),pqcprivkey.getLayers());
            sw = new StringWriter();
            PemHeader pqcpkeyHeader = new PemHeader("PQC Key Type","RAINBOW");
            List<PemHeader> headers = new ArrayList<PemHeader>();
            headers.add(pqcpkeyHeader);
            PemObject peminfo = new PemObject("PQC Private Key",headers,pqcprivkeyinfo.getEncoded("DER"));
            PemWriter pqcpemWriter = new PemWriter(sw);
            pqcpemWriter.writeObject(peminfo);
            pqcpemWriter.flush();
            this.certPqcPrivateKey = sw.toString();
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