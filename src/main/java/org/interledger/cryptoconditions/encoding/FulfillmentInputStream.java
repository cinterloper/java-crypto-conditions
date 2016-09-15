package org.interledger.cryptoconditions.encoding;



import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.IllegalFulfillmentException;
import org.interledger.cryptoconditions.UnsupportedConditionException;
import org.interledger.cryptoconditions.UnsupportedLengthException;
import org.interledger.cryptoconditions.crypto.Ed25519Signature;
import org.interledger.cryptoconditions.impl.Ed25519Fulfillment;
import org.interledger.cryptoconditions.impl.PrefixSha256Fulfillment;
import org.interledger.cryptoconditions.impl.PreimageSha256Fulfillment;
import org.interledger.cryptoconditions.impl.RsaSha256Fulfillment;

import net.i2p.crypto.eddsa.EdDSAPublicKey;
/**
 * Reads and decodes Fulfillments from an underlying input stream.
 * 
 * Fulfillments are expected to be OER encoded on the stream
 * 
 * @see Fulfillment
 * @author adrianhopebailie
 *
 */
public class FulfillmentInputStream extends OerInputStream {
	
	public FulfillmentInputStream(InputStream stream) {
		super(stream);
	}
	
	/**
	 * Read a fulfillment from the underlying stream using OER encoding
	 * per the specification:
	 * 
	 * Fulfillment ::= SEQUENCE {
	 *     type ConditionType,
	 *     payload OCTET STRING
	 * }
	 * 
	 * ConditionType ::= INTEGER {
	 *     preimageSha256(0),
	 *     rsaSha256(1),
	 *     prefixSha256(2),
	 *     thresholdSha256(3),
	 *     ed25519(4)
	 * } (0..65535)
	 * 
	 * @throws IOException
	 * @throws OerDecodingException
	 * @throws UnsupportedConditionException
	 * @throws IllegalFulfillmentException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchAlgorithmException 
	 */
	public Fulfillment readFulfillment()
	        throws IOException, UnsupportedConditionException, OerDecodingException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalFulfillmentException 
	{
		ConditionType type = readConditiontype();
		switch (type) {
			case PREIMAGE_SHA256:
				return readPreimageSha256FulfillmentPayload();
				
			case PREFIX_SHA256:
				return readPrefixSha256FulfillmentPayload();
				
			case RSA_SHA256:
				return readRsaSha256FulfillmentPayload();
				
			case ED25519:
				return readEd25519FulfillmentPayload();
				
			case THRESHOLD_SHA256:
				//TODO return readThresholdSha256Fulfillment;
			default:
				throw new RuntimeException("Unimplemented fulfillment type encountered.");
		}
		
	}

	public PreimageSha256Fulfillment readPreimageSha256FulfillmentPayload()
			throws IOException, UnsupportedLengthException, IllegalLengthIndicatorException {
		
		PreimageSha256Fulfillment fulfillment = new PreimageSha256Fulfillment();
		
		fulfillment.setPreimage(readPayload());
		
		return fulfillment;
	}
	
	public PrefixSha256Fulfillment readPrefixSha256FulfillmentPayload() 
			throws IOException, UnsupportedConditionException, OerDecodingException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalFulfillmentException {
		
		PrefixSha256Fulfillment fulfillment = new PrefixSha256Fulfillment();
		
		//Read the length indicator off the stream
		readLengthIndicator();
		
		fulfillment.setPrefix(readOctetString());
		fulfillment.setSubFulfillment(readFulfillment());
		
		return fulfillment;
		
	}
	
	public RsaSha256Fulfillment readRsaSha256FulfillmentPayload() 
			throws IOException, UnsupportedLengthException, IllegalLengthIndicatorException, IllegalFulfillmentException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		RsaSha256Fulfillment fulfillment = new RsaSha256Fulfillment();
		
		//Read the length indicator off the stream
		readLengthIndicator();
		
		byte[] modulusBytes = readOctetString(
				RsaSha256Fulfillment.MINIMUM_MODULUS_SIZE, 
				RsaSha256Fulfillment.MAXIMUM_MODULUS_SIZE);
						
		byte[] signatureBytes = readOctetString(
				RsaSha256Fulfillment.MINIMUM_SIGNATURE_SIZE, 
				RsaSha256Fulfillment.MAXIMUM_SIGNATURE_SIZE);
		
		if(modulusBytes.length != signatureBytes.length)
			throw new IllegalFulfillmentException("Modulus and signature must be the same size.");
		
		BigInteger modulus = new BigInteger(modulusBytes);
		BigInteger signature = new BigInteger(signatureBytes);
		
		if(modulus.compareTo(signature) <= 0)
			throw new IllegalFulfillmentException("Signature must be numerically smaller than modulus.");
		
		fulfillment.setPublicKey(RsaSha256Fulfillment.getPublicKeyFromModulus(modulus));
		fulfillment.setSignature(signatureBytes);
		
		return fulfillment;
		
	}

	public Ed25519Fulfillment readEd25519FulfillmentPayload() 
			throws IOException, UnsupportedLengthException, IllegalLengthIndicatorException {
		
		Ed25519Fulfillment fulfillment = new Ed25519Fulfillment();
		
		//Read the length indicator off the stream
		readLengthIndicator();
		
		byte[] publicKeyBytes = readOctetString(Ed25519Fulfillment.PUBKEY_LENGTH);
		EdDSAPublicKey key = Ed25519Signature.getPublicKeyFromBytes(publicKeyBytes);
		
		fulfillment.setPublicKey(key);
		fulfillment.setSignature(readOctetString(Ed25519Fulfillment.SIGNATURE_LENGTH));
		
		return fulfillment;
		
	}

	protected ConditionType readConditiontype() 
			throws IOException {
		int value = read16BitUInt();
		return ConditionType.valueOf(value);
	}	

	protected byte[] readPayload() 
			throws IOException, UnsupportedLengthException, IllegalLengthIndicatorException {
		
		return readOctetString();
	}
	
}
