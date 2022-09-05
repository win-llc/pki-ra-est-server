package com.winllc.ra.est.io;

import org.bouncycastle.cms.CMSSignedDataGenerator;

import javax.inject.Provider;

public class CMSSignedDataGeneratorProvider implements Provider<CMSSignedDataGenerator> {
    public CMSSignedDataGenerator get() {
        return new CMSSignedDataGenerator();
    }
}
