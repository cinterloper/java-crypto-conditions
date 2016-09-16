package org.interledger.cryptoconditions.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.crypto.RsaPssSignature;
import org.interledger.cryptoconditions.crypto.Sha256Digest;
import org.interledger.cryptoconditions.encoding.ConditionOutputStream;

/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class RsaSha256Fulfillment implements Fulfillment {

	private static ConditionType TYPE = ConditionType.RSA_SHA256;	
	private static EnumSet<FeatureSuite> FEATURES = EnumSet.of(
			FeatureSuite.SHA_256, 
			FeatureSuite.RSA_PSS
		);
	
	public static BigInteger RSA_PUBLIC_EXPONENT = BigInteger.valueOf(65537);
	
	public static int MINIMUM_MODULUS_SIZE = 128;
	public static int MAXIMUM_MODULUS_SIZE = 512;
	public static int MINIMUM_SIGNATURE_SIZE = 128;
	public static int MAXIMUM_SIGNATURE_SIZE = 512;

	private RSAPublicKey publicKey;
	private byte[] signature;
				
	public void setPublicKey(RSAPublicKey publicKey)
	{
		this.publicKey = publicKey;
	}
	
	public RSAPublicKey getPublicKey() {
		return this.publicKey;
	}
	
	public void setSignature(byte[] signature)
	{
		this.signature = signature;
	}
	
	public byte[] getSignature() {
		return signature;
	}
	
	@Override
	public ConditionType getType() {
		return TYPE;
	}

	@Override
	public Condition computeCondition() {
		
		if (getPublicKey() == null)
			throw new NullPointerException("Public Key is null.");
		
		byte[] fingerprint = Sha256Digest.getDigest(
				calculateFingerPrintContent(getPublicKey().getModulus().toByteArray()));
		
		int maxFulfillmentLength = 
				MAXIMUM_SIGNATURE_SIZE + 2 //Max + Length indicator
				+ MAXIMUM_MODULUS_SIZE + 2; //Max + Length indicator
	
		return new ConditionImpl(
				TYPE, 
				FEATURES, 
				fingerprint, 
				maxFulfillmentLength);
	}
	
	private byte[] calculateFingerPrintContent(byte[] modulus)
	{
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ConditionOutputStream stream = new ConditionOutputStream(buffer);
		
		try {
			stream.writeOctetString(modulus);
			stream.flush();
			return buffer.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}
	
	@Override
	public boolean validate(byte[] message) {
		if (getPublicKey() == null) {
			throw new NullPointerException("Public Key is null.");
		}
		if (getSignature() == null) {
			throw new NullPointerException("Signature is null.");
		}
				
		try {
			return RsaPssSignature.verify(getPublicKey(), message, getSignature());
		} catch (Exception e) {
			throw new RuntimeException(e.toString(), e);
		}
	}
	
	public static RsaSha256Fulfillment fromPrivateKeyAndMessage(RSAPrivateKey privateKey, byte[] message) {
		
		//Check that this private key will work with a public key using a fixed exponent of RSA_PUBLIC_EXPONENT
		if(!isValidPrivateKey(privateKey, RSA_PUBLIC_EXPONENT))
			throw new IllegalArgumentException("The RSASha256 Fulfillment has a fixed public exponent which "
					+ "makes it incompatible with the given private key.");
		
		RSAPublicKey publicKey = getPublicKeyFromModulus(privateKey.getModulus());
		
		byte[] signature;
		try {
			signature = RsaPssSignature.sign(privateKey, message);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		
		RsaSha256Fulfillment f = new RsaSha256Fulfillment();
		f.setPublicKey(publicKey);
		f.setSignature(signature);
		return f;
		
	}
	
	public static RSAPublicKey getPublicKeyFromModulus(BigInteger modulus) {
		
		RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, RSA_PUBLIC_EXPONENT);
		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance("RSA");
			return (RSAPublicKey) kf.generatePublic(spec);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
			
		} catch (InvalidKeySpecException e) {
			
			//TODO check modulus before hand so this can't happen
			throw new RuntimeException(e);
		}
	}

	private static boolean isValidPrivateKey(RSAPrivateKey privateKey, BigInteger pubExponent) {
		
		BigInteger privExponent = privateKey.getPrivateExponent();
		BigInteger sharedModulus = privateKey.getModulus();
		
		BigInteger calc = BigInteger.valueOf(2).modPow(
				(pubExponent.multiply(privExponent)).subtract(BigInteger.ONE), 
				sharedModulus);

		return BigInteger.ONE.equals(calc);
	}
	
}
