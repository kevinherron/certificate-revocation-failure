package com.kevinherron;

import java.io.InputStream;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class RevocationCheckFailure {

    public static void main(String[] args) throws Exception {
        X509Certificate ca1 = decodeCertificate(RevocationCheckFailure.class.getResourceAsStream(
            "/IOP-2020%20CA%20%5B58EDFC459FFFBCD22F3C008285BE6D1D9B39F102%5D.der"
        ));
        X509CRL crl1 = decodeCRL(RevocationCheckFailure.class.getResourceAsStream(
            "/IOP-2020%20CA%20%5B58EDFC459FFFBCD22F3C008285BE6D1D9B39F102%5D.crl"
        ));

        X509Certificate ca2 = decodeCertificate(RevocationCheckFailure.class.getResourceAsStream(
            "/IOP-2020%20CA%20%5BA198BE34B3057739218824D23DA124C6F2D72D72%5D.der"
        ));
        X509CRL crl2 = decodeCRL(RevocationCheckFailure.class.getResourceAsStream(
            "/IOP-2020%20CA%20%5BA198BE34B3057739218824D23DA124C6F2D72D72%5D.crl"
        ));

        X509Certificate cert = decodeCertificate(RevocationCheckFailure.class.getResourceAsStream(
            "/8e2c143f029cf142ee5fc88fc7525e9542e54bc5 [CN%3DUA+Core+Complex+Client].der"
        ));

        Set<TrustAnchor> trustAnchors = new HashSet<>();
        trustAnchors.add(new TrustAnchor(ca1, null));
        trustAnchors.add(new TrustAnchor(ca2, null));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(cert);

        PKIXBuilderParameters builderParams = new PKIXBuilderParameters(trustAnchors, selector);

        // Disable revocation checking in the CertPathBuilder; it will be
        // checked by a PKIXCertPathValidator after the CertPath is built.
        builderParams.setRevocationEnabled(false);

        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(builderParams);
        CertPath certPath = result.getCertPath();
        TrustAnchor trustAnchor = result.getTrustAnchor();

        CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX", "SUN");
        PKIXParameters pkixParams = new PKIXParameters(Set.of(trustAnchor));
        pkixParams.setRevocationEnabled(true);

        // Remove crl2 from this list and validation will succeed
        pkixParams.addCertStore(CertStore.getInstance(
            "Collection",
            new CollectionCertStoreParameters(List.of(crl1, crl2))
        ));

        certPathValidator.validate(certPath, pkixParams);
    }

    public static X509Certificate decodeCertificate(InputStream inputStream) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(inputStream);
    }

    private static X509CRL decodeCRL(InputStream inputStream) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509CRL) factory.generateCRL(inputStream);
    }

}
