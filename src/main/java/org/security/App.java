package org.security;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

/**
 * Hello world!
 *
 */
public class App {

	Logger logger = Logger.getLogger(App.class.getName());

	private KeyStore keystore;
	private String password = "wso2carbon";

	public static void main(String[] args) {
		System.out.println("Hello World!");
	}

	public String sign(byte[] dataToSign, String keyAlias) throws Exception {
		try {

			ClassLoader classLoader = getClass().getClassLoader();

			InputStream targetStream = classLoader.getResourceAsStream("wso2carbon.jks");

			keystore = KeyStore.getInstance("JKS");
			keystore.load(targetStream, password.toCharArray());

			CMSProcessable content = new CMSProcessableByteArray(dataToSign);
			CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
			X509Certificate cert = null;
			PrivateKey key = null;
	        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			List<X509Certificate> certList = new ArrayList<X509Certificate>();
			cert = (X509Certificate) keystore.getCertificate(keyAlias);
			key = (PrivateKey) keystore.getKey(keyAlias, password.toCharArray());
			certList.add(cert);
			generator.addSigner(key, cert, CMSSignedGenerator.DIGEST_SHA1);
			CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
			generator.addCertificatesAndCRLs(store);
			CMSSignedData signed = generator.generate(content, true, (Provider) null);
			byte[] result = signed.getEncoded();
			return Base64.getEncoder().encodeToString(result);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "An error occurred trying to sign user data: ", e);

			throw new Exception("Failed to sign user data", e);
		}
	}

}
