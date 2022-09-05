package com.winllc.ra.est.io;

import com.winllc.ra.est.protocol.CertificationRequest;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.io.InputStream;

public class BouncyCastleCertificateRequestDecoder implements EntityDecoder<CertificationRequest> {
    @Override
    public CertificationRequest decode(InputStream in) throws IOException {
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(IOUtils.toByteArray(in));
        if (csr == null) {
            throw new IOException("Failed to parse CSR");
        }
        final byte[] bytes = csr.getEncoded();

        return new CertificationRequest() {
            @Override
            public byte[] getBytes() {
                return bytes;
            }
        };
    }
}
