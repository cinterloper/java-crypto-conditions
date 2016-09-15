package org.interledger.cryptoconditions.crypto;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class Ed25519Signature {

	public static final EdDSAParameterSpec ED25519_SHA_512_SIGNATURE_PARAMETERS = 
			EdDSANamedCurveTable.getByName("ed25519-sha-512");
	
	public static EdDSAPrivateKey getPrivateKeyFromBytes(byte[] privateKeyBytes) {
		EdDSAPrivateKeySpec privateKeySpec = new EdDSAPrivateKeySpec(privateKeyBytes, ED25519_SHA_512_SIGNATURE_PARAMETERS);
		return new EdDSAPrivateKey(privateKeySpec);
	}
	
	public static EdDSAPublicKey getPublicKeyFromPrivateKey(EdDSAPrivateKey privateKey) {
		EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privateKey.getA(), ED25519_SHA_512_SIGNATURE_PARAMETERS); 
		return new EdDSAPublicKey(pubKeySpec);
	}
	
	public static EdDSAPublicKey getPublicKeyFromBytes(byte[] publicKeyBytes) {
		EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(publicKeyBytes, ED25519_SHA_512_SIGNATURE_PARAMETERS);
		return new EdDSAPublicKey(pubKeySpec);
	}
	
	public static byte[] sign(byte[] privateKeyBytes, byte[] material) 
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		return sign(getPrivateKeyFromBytes(privateKeyBytes), material);
	}
	
	public static byte[] sign(EdDSAPrivateKey privateKey, byte[] material) 
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature sgr = new EdDSAEngine(MessageDigest.getInstance(Sha256Digest.ALGORITHM_NAME));
		sgr.initSign(privateKey);
		sgr.update(material);
		return sgr.sign();
	}

	public static boolean verify(EdDSAPublicKey publicKey, byte[] data, byte[] signature) throws Exception {
		Signature sgr = new EdDSAEngine(MessageDigest.getInstance(Sha256Digest.ALGORITHM_NAME));
		sgr.initVerify(publicKey);
		sgr.update(data);
		return sgr.verify(signature);
	}

}