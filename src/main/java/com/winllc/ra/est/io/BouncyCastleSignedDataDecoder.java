package com.winllc.ra.est.io;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class BouncyCastleSignedDataDecoder implements EntityDecoder<X509Certificate[]> {
    @Override
    public X509Certificate[] decode(InputStream in) throws IOException {
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        try {
            CMSSignedData signedData = new CMSSignedData(in);
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

            Collection<?> certHolders = signedData.getCertificates().getMatches(null);

            for (Object certHolder : certHolders) {
                certs.add(converter.getCertificate((X509CertificateHolder) certHolder));
            }
        } catch (CMSException e) {
            throw new IOException(e);
        } catch (CertificateException e) {
            throw new IOException(e);
        }
        return certs.toArray(new X509Certificate[certs.size()]);
    }
}
