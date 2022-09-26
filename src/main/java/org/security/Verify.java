package org.security;

import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Iterator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Verify {

	  private static final Logger log = LogManager.getLogger(Verify.class);  
	
	
	public String getSignedData(String data) {
		 
		 
		try {
		byte[] b =  Base64.getDecoder().decode(data);
		// get the PKCS7 envelope
		CMSSignedData pkcs7Envelope = new CMSSignedData(b);
		// get certificate store
		CertStore certs = pkcs7Envelope.getCertificatesAndCRLs("Collection",  BouncyCastleProvider.PROVIDER_NAME);
		// get the set of SignerInfo
		SignerInformationStore signers = pkcs7Envelope.getSignerInfos();
		// if there is none or more than one signer return null
		if (signers == null || signers.size() != 1) {
		log.error("SecurityUtils: None or more then one signer ");
		return null;
		}
		// get the signer
		Collection<?> c = signers.getSigners();
		Iterator<?> it = c.iterator();
		SignerInformation signerInfo = (SignerInformation) it.next();
		// get the certificate of the signer based on signer id
		Collection<?> certCollection = certs.getCertificates(signerInfo.getSID());
		Iterator<?> certIt = certCollection.iterator();
		X509Certificate inputX09Certificate = (X509Certificate) certIt.next();
		// if no signer is found return null
		if (inputX09Certificate == null) {
		log.error("SecurityUtils: No signer found ");
		return null;
		}
		
		// get the owner of the certificate
//		try {
//		String owner = getX500Map(inputX09Certificate.getSubjectX500Principal()).get(
//		securityParams.get("ownerIdentifier"));
		// if there is no owner for this certificate return null
//		if (owner == null) {
//		log.error("SecurityUtils: No owner found for this certificate"
//		+ inputX09Certificate);
//		return null;
//		}
		// check for owner rights
//		if (!signerAllowed(owner)) {
//		log.error("SecurityUtils: Owner of certificate not allowed to sign: " + owner);
//		return null;
//		}
	 
		} catch (Exception e) {
		log.error("SecurityUtils: Cannot obtain signer certificate subjectX500Principal: "
		+ " ", e);
		return null;
		}
		// check certificate validity
//		if (checkCert) {
//		try {
//		certVerifier.verifyCertChain(inputX09Certificate, 5, warningValidationDate,
//		errorValidationDate, null);
//		} catch (Exception e) {
//		log.error("SecurityUtils: Certificate chain verification failed " + " ", e);
//		return null;
//		}
//		}
		// check signature data
//		if (!signerInfo.verify(inputX09Certificate, "BC")) {
//		log.error("SecurityUtils: Signature failed to verify ");
//		return null;
//		}
//		return new String((byte[]) pkcs7Envelope.getSignedContent().getContent());
//		} catch (Exception e) {
//		log.error("Cannot verify signed data: \n" + "" + "\n" + e, e);
//		log.info("");
//		return null;
//		}
		return null;
		}
}
