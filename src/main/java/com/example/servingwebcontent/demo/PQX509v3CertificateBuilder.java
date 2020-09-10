package com.example.servingwebcontent.demo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.bouncycastle.cert.*;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowSigner;
import org.bouncycastle.util.Properties;

import javassist.bytecode.ByteArray;

/**
 * class to produce an X.509 Version 3 certificate.
 */
public class PQX509v3CertificateBuilder {
    private V3TBSCertificateGenerator tbsGen;
    private ExtensionsGenerator extGenerator;
    private RainbowPublicKeyParameters pqcpublickey;

    /**
     * Create a builder for a version 3 certificate.
     *
     * @param issuer        the certificate issuer
     * @param serial        the certificate serial number
     * @param notBefore     the date before which the certificate is not valid
     * @param notAfter      the date after which the certificate is not valid
     * @param subject       the certificate subject
     * @param publicKeyInfo the info structure for the public key to be associated
     *                      with this certificate.
     */
    public PQX509v3CertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter,
            X500Name subject, SubjectPublicKeyInfo publicKeyInfo) {
        this(issuer, serial, new Time(notBefore), new Time(notAfter), subject, publicKeyInfo);
    }

    /**
     * Create a builder for a version 3 certificate. You may need to use this
     * constructor if the default locale doesn't use a Gregorian calender so that
     * the Time produced is compatible with other ASN.1 implementations.
     *
     * @param issuer        the certificate issuer
     * @param serial        the certificate serial number
     * @param notBefore     the date before which the certificate is not valid
     * @param notAfter      the date after which the certificate is not valid
     * @param dateLocale    locale to be used for date interpretation.
     * @param subject       the certificate subject
     * @param publicKeyInfo the info structure for the public key to be associated
     *                      with this certificate.
     */
    public PQX509v3CertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter,
            Locale dateLocale, X500Name subject, SubjectPublicKeyInfo publicKeyInfo) {
        this(issuer, serial, new Time(notBefore, dateLocale), new Time(notAfter, dateLocale), subject, publicKeyInfo);
    }

    /**
     * Create a builder for a version 3 certificate.
     *
     * @param issuer        the certificate issuer
     * @param serial        the certificate serial number
     * @param notBefore     the Time before which the certificate is not valid
     * @param notAfter      the Time after which the certificate is not valid
     * @param subject       the certificate subject
     * @param publicKeyInfo the info structure for the public key to be associated
     *                      with this certificate.
     */
    public PQX509v3CertificateBuilder(X500Name issuer, BigInteger serial, Time notBefore, Time notAfter,
            X500Name subject, SubjectPublicKeyInfo publicKeyInfo) {
        tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(serial));
        tbsGen.setIssuer(issuer);
        tbsGen.setStartDate(notBefore);
        tbsGen.setEndDate(notAfter);
        tbsGen.setSubject(subject);
        tbsGen.setSubjectPublicKeyInfo(publicKeyInfo);

        extGenerator = new ExtensionsGenerator();
    }

    /**
     * Create a builder for a version 3 certificate, initialised with another
     * certificate.
     *
     * @param template template certificate to base the new one on.
     */
    public PQX509v3CertificateBuilder(X509CertificateHolder template) {
        tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(template.getSerialNumber()));
        tbsGen.setIssuer(template.getIssuer());
        tbsGen.setStartDate(new Time(template.getNotBefore()));
        tbsGen.setEndDate(new Time(template.getNotAfter()));
        tbsGen.setSubject(template.getSubject());
        tbsGen.setSubjectPublicKeyInfo(template.getSubjectPublicKeyInfo());

        extGenerator = new ExtensionsGenerator();

        Extensions exts = template.getExtensions();

        for (Enumeration en = exts.oids(); en.hasMoreElements();) {
            extGenerator.addExtension(exts.getExtension((ASN1ObjectIdentifier) en.nextElement()));
        }
    }

    /**
     * Initialise the builder using a PublicKey.
     *
     * @param issuer    X500Name representing the issuer of this certificate.
     * @param serial    the serial number for the certificate.
     * @param notBefore date before which the certificate is not valid.
     * @param notAfter  date after which the certificate is not valid.
     * @param subject   X500Name representing the subject of this certificate.
     * @param publicKey the public key to be associated with the certificate.
     */
    public PQX509v3CertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter,
            X500Name subject, AsymmetricKeyParameter publicKey) throws IOException {
        this(issuer, serial, notBefore, notAfter, subject,
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));
    }

    /**
     * Initialise the builder using the subject from the passed in issuerCert as the
     * issuer, as well as passing through and converting the other objects provided.
     *
     * @param issuerCert holder for certificate who's subject is the issuer of the
     *                   certificate we are building.
     * @param serial     the serial number for the certificate.
     * @param notBefore  date before which the certificate is not valid.
     * @param notAfter   date after which the certificate is not valid.
     * @param subject    principal representing the subject of this certificate.
     * @param publicKey  the public key to be associated with the certificate.
     */
    public PQX509v3CertificateBuilder(X509CertificateHolder issuerCert, BigInteger serial, Date notBefore,
            Date notAfter, X500Name subject, AsymmetricKeyParameter publicKey) throws IOException {
        this(issuerCert.getSubject(), serial, notBefore, notAfter, subject,
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));
    }

    public PQX509v3CertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter,
            X500Name subject, AsymmetricKeyParameter publicKey, RainbowPublicKeyParameters pqcpublickey)
            throws IOException {
        this(issuer, serial, notBefore, notAfter, subject,
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));
        this.pqcpublickey = pqcpublickey;
    }

    /**
     * Return if the extension indicated by OID is present.
     *
     * @param oid the OID for the extension of interest.
     * @return the Extension, or null if it is not present.
     */
    public boolean hasExtension(ASN1ObjectIdentifier oid) {
        return doGetExtension(oid) != null;
    }

    /**
     * Return the current value of the extension for OID.
     *
     * @param oid the OID for the extension we want to fetch.
     * @return true if a matching extension is present, false otherwise.
     */
    public Extension getExtension(ASN1ObjectIdentifier oid) {
        return doGetExtension(oid);
    }

    private Extension doGetExtension(ASN1ObjectIdentifier oid) {
        Extensions exts = extGenerator.generate();

        return exts.getExtension(oid);
    }

    /**
     * Set the subjectUniqueID - note: it is very rare that it is correct to do
     * this.
     *
     * @param uniqueID a boolean array representing the bits making up the
     *                 subjectUniqueID.
     * @return this builder object.
     */
    public PQX509v3CertificateBuilder setSubjectUniqueID(boolean[] uniqueID) {
        tbsGen.setSubjectUniqueID(booleanToBitString(uniqueID));

        return this;
    }

    /**
     * Set the issuerUniqueID - note: it is very rare that it is correct to do this.
     *
     * @param uniqueID a boolean array representing the bits making up the
     *                 issuerUniqueID.
     * @return this builder object.
     */
    public PQX509v3CertificateBuilder setIssuerUniqueID(boolean[] uniqueID) {
        tbsGen.setIssuerUniqueID(booleanToBitString(uniqueID));

        return this;
    }

    /**
     * Add a given extension field for the standard extensions tag (tag 3)
     *
     * @param oid        the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param value      the ASN.1 structure that forms the extension's value.
     * @return this builder object.
     * @throws CertIOException          if there is an issue with the new extension
     *                                  value.
     * @throws IllegalArgumentException if the OID oid has already been used.
     */
    public PQX509v3CertificateBuilder addExtension(ASN1ObjectIdentifier oid, boolean isCritical, ASN1Encodable value)
            throws CertIOException {
        try {
            extGenerator.addExtension(oid, isCritical, value);
        } catch (IOException e) {
            throw new CertIOException("cannot encode extension: " + e.getMessage(), e);
        }

        return this;
    }

    /**
     * Add a given extension field for the standard extensions tag (tag 3).
     *
     * @param extension the full extension value.
     * @return this builder object.
     * @throws CertIOException          if there is an issue with the new extension
     *                                  value.
     * @throws IllegalArgumentException if the OID oid has already been used.
     */
    public PQX509v3CertificateBuilder addExtension(Extension extension) throws CertIOException {
        extGenerator.addExtension(extension);

        return this;
    }

    /**
     * Add a given extension field for the standard extensions tag (tag 3) using a
     * byte encoding of the extension value.
     *
     * @param oid          the OID defining the extension type.
     * @param isCritical   true if the extension is critical, false otherwise.
     * @param encodedValue a byte array representing the encoding of the extension
     *                     value.
     * @return this builder object.
     * @throws CertIOException          if there is an issue with the new extension
     *                                  value.
     * @throws IllegalArgumentException if the OID oid has already been allocated.
     */
    public PQX509v3CertificateBuilder addExtension(ASN1ObjectIdentifier oid, boolean isCritical, byte[] encodedValue)
            throws CertIOException {
        extGenerator.addExtension(oid, isCritical, encodedValue);

        return this;
    }

    /**
     * Replace the extension field for the passed in extension's extension ID with a
     * new version.
     *
     * @param oid        the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param value      the ASN.1 structure that forms the extension's value.
     * @return this builder object.
     * @throws CertIOException          if there is an issue with the new extension
     *                                  value.
     * @throws IllegalArgumentException if the extension to be replaced is not
     *                                  present.
     */
    public PQX509v3CertificateBuilder replaceExtension(ASN1ObjectIdentifier oid, boolean isCritical,
            ASN1Encodable value) throws CertIOException {
        try {
            extGenerator = CertUtils.doReplaceExtension(extGenerator,
                    new Extension(oid, isCritical, value.toASN1Primitive().getEncoded(ASN1Encoding.DER)));
        } catch (IOException e) {
            throw new CertIOException("cannot encode extension: " + e.getMessage(), e);
        }

        return this;
    }

    /**
     * Replace the extension field for the passed in extension's extension ID with a
     * new version.
     *
     * @param extension the full extension value.
     * @return this builder object.
     * @throws CertIOException          if there is an issue with the new extension
     *                                  value.
     * @throws IllegalArgumentException if the extension to be replaced is not
     *                                  present.
     */
    public PQX509v3CertificateBuilder replaceExtension(Extension extension) throws CertIOException {
        extGenerator = CertUtils.doReplaceExtension(extGenerator, extension);

        return this;
    }

    /**
     * Replace a given extension field for the standard extensions tag (tag 3) with
     * the passed in byte encoded extension value.
     *
     * @param oid          the OID defining the extension type.
     * @param isCritical   true if the extension is critical, false otherwise.
     * @param encodedValue a byte array representing the encoding of the extension
     *                     value.
     * @return this builder object.
     * @throws CertIOException          if there is an issue with the new extension
     *                                  value.
     * @throws IllegalArgumentException if the extension to be replaced is not
     *                                  present.
     */
    public PQX509v3CertificateBuilder replaceExtension(ASN1ObjectIdentifier oid, boolean isCritical,
            byte[] encodedValue) throws CertIOException {
        extGenerator = CertUtils.doReplaceExtension(extGenerator, new Extension(oid, isCritical, encodedValue));

        return this;
    }

    /**
     * Remove the extension indicated by OID.
     *
     * @param oid the OID of the extension to be removed.
     * @return this builder object.
     * @throws IllegalArgumentException if the extension to be removed is not
     *                                  present.
     */
    public PQX509v3CertificateBuilder removeExtension(ASN1ObjectIdentifier oid) {
        extGenerator = CertUtils.doRemoveExtension(extGenerator, oid);

        return this;
    }

    /**
     * Add a given extension field for the standard extensions tag (tag 3) copying
     * the extension value from another certificate.
     *
     * @param oid        the OID defining the extension type.
     * @param isCritical true if the copied extension is to be marked as critical,
     *                   false otherwise.
     * @param certHolder the holder for the certificate that the extension is to be
     *                   copied from.
     * @return this builder object.
     */
    public PQX509v3CertificateBuilder copyAndAddExtension(ASN1ObjectIdentifier oid, boolean isCritical,
            X509CertificateHolder certHolder) {
        Certificate cert = certHolder.toASN1Structure();

        Extension extension = cert.getTBSCertificate().getExtensions().getExtension(oid);

        if (extension == null) {
            throw new NullPointerException("extension " + oid + " not present");
        }

        extGenerator.addExtension(oid, isCritical, extension.getExtnValue().getOctets());

        return this;
    }

    /**
     * Generate an X.509 certificate, based on the current issuer and subject using
     * the passed in signer.
     *
     * @param signer    the content signer to be used to generate the signature
     *                  validating the certificate.
     * @param pqcsigner
     * @return a holder containing the resulting signed certificate.
     */
    public X509CertificateHolder build(ContentSigner signer, RainbowSigner pqcsigner,
            RainbowPrivateKeyParameters pqcprivatekey) {
        tbsGen.setSignature(signer.getAlgorithmIdentifier());

        if (!extGenerator.isEmpty()) {
            tbsGen.setExtensions(extGenerator.generate());
        }

        try {
            TBSCertificate tbsCert = tbsGen.generateTBSCertificate();
            return new X509CertificateHolder(generateStructure(tbsCert, signer.getAlgorithmIdentifier(),
                    generateSig(signer, tbsCert), generatePQSig(pqcsigner, tbsCert, pqcprivatekey)));
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot produce certificate signature");
        }
    }

    private static byte[] generatePQSig(RainbowSigner pqcsigner, ASN1Object tbsObj,
            RainbowPrivateKeyParameters pqcprivkey) throws IOException {
        ByteArrayOutputStream sOut = new ByteArrayOutputStream();
        tbsObj.encodeTo(sOut, ASN1Encoding.DER);
        // This is where I am lost; looking at RainbowSigner I can't figure out how the
        // message is
        // hashed before signing when using the method directly (there is no method to
        // choose which hash algorithm is
        // to be used by RainbowSigner. Until I get that figured out, I'll hash the
        // message before I pass it over to the
        // signer).
        SHA512Digest sha512Digest = new SHA512Digest();
        sha512Digest.update(sOut.toByteArray(), 0, sOut.toByteArray().length);
        byte[] digest = new byte[sha512Digest.getDigestSize()];
        sha512Digest.doFinal(digest, 0);
        // Sign the certificate with the pqc private key
        pqcsigner.init(true, pqcprivkey);
        byte[] pqcsig = pqcsigner.generateSignature(digest);
        return pqcsig;
    }

    private static byte[] generateSig(ContentSigner signer, ASN1Object tbsObj) throws IOException {
        OutputStream sOut = signer.getOutputStream();
        tbsObj.encodeTo(sOut, ASN1Encoding.DER);
        sOut.close();

        return signer.getSignature();
    }

    private static Certificate generateStructure(TBSCertificate tbsCert, AlgorithmIdentifier sigAlgId, byte[] signature,
            byte[] pqcsignature) throws UnsupportedEncodingException {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCert);
        v.add(sigAlgId);
        // Bouncycastle ASN1 certificate encoder implements a check to ensure that the sequence in the
        // vector to encode only has 3 elements, the cert itself, the signature algorithm identifier and
        // the signature. So to embed the PQC signature, we can either a) add it as an extension to the
        // tbsCert itself (which would make the cert work for legacy systems that can't parse the extension
        // to get the PQC signature, well known method that was drafted in IETF) or we can combine both
        // signatures in the signature block, which will be unparseable by clients that aren't updated
        // to understand the new signature. Let's experiment!
        ByteArrayOutputStream hybridSig = new ByteArrayOutputStream();
        hybridSig.write(signature, 0, signature.length);
        // Add a delimeter sequence between the signatures
        String delim = "hybriddelim";
        byte[] delimb = delim.getBytes("UTF-8");
        hybridSig.write(delimb,0,delimb.length);
        hybridSig.write(pqcsignature,0, pqcsignature.length);
        v.add(new DERBitString(hybridSig.toByteArray()));
        
        return Certificate.getInstance(new DERSequence(v));
    }

    static DERBitString booleanToBitString(boolean[] id) {
        byte[] bytes = new byte[(id.length + 7) / 8];

        for (int i = 0; i != id.length; i++) {
            bytes[i / 8] |= (id[i]) ? (1 << ((7 - (i % 8)))) : 0;
        }

        int pad = id.length % 8;

        if (pad == 0) {
            return new DERBitString(bytes);
        } else {
            return new DERBitString(bytes, 8 - pad);
        }
    }

    static class CertUtils {
        private static Set EMPTY_SET = Collections.unmodifiableSet(new HashSet());
        private static List EMPTY_LIST = Collections.unmodifiableList(new ArrayList());

        static ASN1Primitive parseNonEmptyASN1(byte[] encoding) throws IOException {
            ASN1Primitive p = ASN1Primitive.fromByteArray(encoding);

            if (p == null) {
                throw new IOException("no content found");
            }
            return p;
        }

        static X509CertificateHolder generateFullCert(ContentSigner signer, TBSCertificate tbsCert) {
            try {
                return new X509CertificateHolder(
                        generateStructure(tbsCert, signer.getAlgorithmIdentifier(), generateSig(signer, tbsCert)));
            } catch (IOException e) {
                throw new IllegalStateException("cannot produce certificate signature");
            }
        }

        static X509AttributeCertificateHolder generateFullAttrCert(ContentSigner signer,
                AttributeCertificateInfo attrInfo) {
            try {
                return new X509AttributeCertificateHolder(generateAttrStructure(attrInfo,
                        signer.getAlgorithmIdentifier(), generateSig(signer, attrInfo)));
            } catch (IOException e) {
                throw new IllegalStateException("cannot produce attribute certificate signature");
            }
        }

        static X509CRLHolder generateFullCRL(ContentSigner signer, TBSCertList tbsCertList) {
            try {
                return new X509CRLHolder(generateCRLStructure(tbsCertList, signer.getAlgorithmIdentifier(),
                        generateSig(signer, tbsCertList)));
            } catch (IOException e) {
                throw new IllegalStateException("cannot produce certificate signature");
            }
        }

        private static byte[] generateSig(ContentSigner signer, ASN1Object tbsObj) throws IOException {
            OutputStream sOut = signer.getOutputStream();
            tbsObj.encodeTo(sOut, ASN1Encoding.DER);
            sOut.close();

            return signer.getSignature();
        }

        private static Certificate generateStructure(TBSCertificate tbsCert, AlgorithmIdentifier sigAlgId,
                byte[] signature) {
            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(tbsCert);
            v.add(sigAlgId);
            v.add(new DERBitString(signature));

            return Certificate.getInstance(new DERSequence(v));
        }

        private static AttributeCertificate generateAttrStructure(AttributeCertificateInfo attrInfo,
                AlgorithmIdentifier sigAlgId, byte[] signature) {
            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(attrInfo);
            v.add(sigAlgId);
            v.add(new DERBitString(signature));

            return AttributeCertificate.getInstance(new DERSequence(v));
        }

        private static CertificateList generateCRLStructure(TBSCertList tbsCertList, AlgorithmIdentifier sigAlgId,
                byte[] signature) {
            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(tbsCertList);
            v.add(sigAlgId);
            v.add(new DERBitString(signature));

            return CertificateList.getInstance(new DERSequence(v));
        }

        static Set getCriticalExtensionOIDs(Extensions extensions) {
            if (extensions == null) {
                return EMPTY_SET;
            }

            return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getCriticalExtensionOIDs())));
        }

        static Set getNonCriticalExtensionOIDs(Extensions extensions) {
            if (extensions == null) {
                return EMPTY_SET;
            }

            // TODO: should probably produce a set that imposes correct ordering
            return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getNonCriticalExtensionOIDs())));
        }

        static List getExtensionOIDs(Extensions extensions) {
            if (extensions == null) {
                return EMPTY_LIST;
            }

            return Collections.unmodifiableList(Arrays.asList(extensions.getExtensionOIDs()));
        }

        static void addExtension(ExtensionsGenerator extGenerator, ASN1ObjectIdentifier oid, boolean isCritical,
                ASN1Encodable value) throws CertIOException {
            try {
                extGenerator.addExtension(oid, isCritical, value);
            } catch (IOException e) {
                throw new CertIOException("cannot encode extension: " + e.getMessage(), e);
            }
        }

        static DERBitString booleanToBitString(boolean[] id) {
            byte[] bytes = new byte[(id.length + 7) / 8];

            for (int i = 0; i != id.length; i++) {
                bytes[i / 8] |= (id[i]) ? (1 << ((7 - (i % 8)))) : 0;
            }

            int pad = id.length % 8;

            if (pad == 0) {
                return new DERBitString(bytes);
            } else {
                return new DERBitString(bytes, 8 - pad);
            }
        }

        static boolean[] bitStringToBoolean(DERBitString bitString) {
            if (bitString != null) {
                byte[] bytes = bitString.getBytes();
                boolean[] boolId = new boolean[bytes.length * 8 - bitString.getPadBits()];

                for (int i = 0; i != boolId.length; i++) {
                    boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
                }

                return boolId;
            }

            return null;
        }

        static Date recoverDate(ASN1GeneralizedTime time) {
            try {
                return time.getDate();
            } catch (ParseException e) {
                throw new IllegalStateException("unable to recover date: " + e.getMessage());
            }
        }

        static boolean isAlgIdEqual(AlgorithmIdentifier id1, AlgorithmIdentifier id2) {
            if (!id1.getAlgorithm().equals(id2.getAlgorithm())) {
                return false;
            }

            if (Properties.isOverrideSet("org.bouncycastle.x509.allow_absent_equiv_NULL")) {
                if (id1.getParameters() == null) {
                    if (id2.getParameters() != null && !id2.getParameters().equals(DERNull.INSTANCE)) {
                        return false;
                    }

                    return true;
                }

                if (id2.getParameters() == null) {
                    if (id1.getParameters() != null && !id1.getParameters().equals(DERNull.INSTANCE)) {
                        return false;
                    }

                    return true;
                }
            }

            if (id1.getParameters() != null) {
                return id1.getParameters().equals(id2.getParameters());
            }

            if (id2.getParameters() != null) {
                return id2.getParameters().equals(id1.getParameters());
            }

            return true;
        }

        static ExtensionsGenerator doReplaceExtension(ExtensionsGenerator extGenerator, Extension ext) {
            boolean isReplaced = false;
            Extensions exts = extGenerator.generate();
            extGenerator = new ExtensionsGenerator();

            for (Enumeration en = exts.oids(); en.hasMoreElements();) {
                ASN1ObjectIdentifier extOid = (ASN1ObjectIdentifier) en.nextElement();

                if (extOid.equals(ext.getExtnId())) {
                    isReplaced = true;
                    extGenerator.addExtension(ext);
                } else {
                    extGenerator.addExtension(exts.getExtension(extOid));
                }
            }

            if (!isReplaced) {
                throw new IllegalArgumentException(
                        "replace - original extension (OID = " + ext.getExtnId() + ") not found");
            }

            return extGenerator;
        }

        static ExtensionsGenerator doRemoveExtension(ExtensionsGenerator extGenerator, ASN1ObjectIdentifier oid) {
            boolean isRemoved = false;
            Extensions exts = extGenerator.generate();
            extGenerator = new ExtensionsGenerator();

            for (Enumeration en = exts.oids(); en.hasMoreElements();) {
                ASN1ObjectIdentifier extOid = (ASN1ObjectIdentifier) en.nextElement();

                if (extOid.equals(oid)) {
                    isRemoved = true;
                } else {
                    extGenerator.addExtension(exts.getExtension(extOid));
                }
            }

            if (!isRemoved) {
                throw new IllegalArgumentException("remove - extension (OID = " + oid + ") not found");
            }

            return extGenerator;
        }
    }
}