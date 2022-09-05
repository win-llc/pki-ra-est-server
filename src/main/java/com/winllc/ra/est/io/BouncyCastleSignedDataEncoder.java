package com.winllc.ra.est.io;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class BouncyCastleSignedDataEncoder implements EntityEncoder<X509Certificate> {
    private final CMSSignedDataGenerator sdGeneratorProvider;

    public BouncyCastleSignedDataEncoder(CMSSignedDataGenerator sdGeneratorProvider) {
        this.sdGeneratorProvider = sdGeneratorProvider;
    }

    public void encode(OutputStream out, X509Certificate... entity) throws IOException {
        try {
            Store store = new JcaCertStore(Arrays.asList(entity));
            sdGeneratorProvider.addCertificates(store);
            CMSSignedData signedData = sdGeneratorProvider.generate(new CMSAbsentContent());

            out.write(signedData.getEncoded());
        } catch (CMSException e) {
            throw new IOException(e);
        } catch (CertificateEncodingException e) {
            throw new IOException(e);
        }
    }
}
