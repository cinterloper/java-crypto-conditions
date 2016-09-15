package org.interledger.cryptoconditions.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RsaPssSignature {
	
	public static final PSSParameterSpec RSASSA_PSS_SIGNATURE_PARAMETERS = 
			new PSSParameterSpec(
				"SHA-256", 
				"MGF1", 
				new MGF1ParameterSpec("SHA-256"), 
				32, 
				1);
		
	public static byte[] sign(RSAPrivateKey privateKey, byte[] material) 
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
		
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.setParameter(RSASSA_PSS_SIGNATURE_PARAMETERS);
		sig.initSign(privateKey);
		sig.update(material);
		return sig.sign();
		
	}

	public static boolean verify(RSAPublicKey publicKey, byte[] data, byte[] signature) 
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
		
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.setParameter(RSASSA_PSS_SIGNATURE_PARAMETERS);
		sig.initVerify(publicKey);
		sig.update(data);
		return sig.verify(signature);
		
	}

}