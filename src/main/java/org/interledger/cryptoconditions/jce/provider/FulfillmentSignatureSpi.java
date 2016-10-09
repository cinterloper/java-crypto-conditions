package org.interledger.cryptoconditions.jce.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;

import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.IllegalFulfillmentException;
import org.interledger.cryptoconditions.UnsupportedConditionException;
import org.interledger.cryptoconditions.jce.interfaces.ConditionPublicKey;
import org.interledger.cryptoconditions.oer.FulfillmentOerOutputStream;
import org.interledger.cryptoconditions.oer.OerDecodingException;
import org.interledger.cryptoconditions.oer.OerUtil;

public abstract class FulfillmentSignatureSpi extends SignatureSpi implements Fulfillment {

	private ConditionPublicKey condition = null;
	private PrivateKey privateKey = null;
	private Signature internalSignature;	
	private ByteArrayOutputStream buffer;	
		
	protected void setInternalSignature(Signature signature) {
		this.internalSignature = signature;
	}
	
	protected Signature getInternalSignature() {
		return this.internalSignature;
	}
	
	@Override
	protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
		if(!(publicKey instanceof ConditionPublicKey)){
            throw new InvalidKeyException("Supplied key is not a Condition.");
		}
		
		condition = (ConditionPublicKey) publicKey;
		
		//Sanity check the condition
		if(!getType().equals(condition.getType())) {
            throw new InvalidKeyException("Supplied key is not a Condition of the correct type.");
		}
		
		if(!getFeatures().containsAll(condition.getFeatures())) {
            throw new InvalidKeyException("Supplied condition has unsupported features.");
		}
		
		if(getSafeFulfillmentLength() < condition.getMaxFulfillmentLength()) {
            throw new InvalidKeyException("Supplied condition has a maximum fulfillment length that is too high (unsafe).");
		}
		
		buffer = new ByteArrayOutputStream();
		
	}

	@Override
	protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {		
		validatePrivateKey(privateKey);
		this.privateKey = privateKey;
		this.internalSignature.initSign(privateKey);
	}
	
	/**
	 * Validate the private key that will be used to generate the internal signature that is
	 * put into the fulfillment.
	 * 
	 * @param privateKey
	 * @throws InvalidKeyException
	 */
	protected abstract void validatePrivateKey(PrivateKey privateKey) throws InvalidKeyException;
	
	/**
	 * Ensure that the signature generated by the internal signature engine is valid.
	 * 
	 * @param privateKey The private key used to generate the signature
	 * @param signature The Signature
	 * @throws SignatureException If the signature is invalid or can't be used to construct a fulfillment
	 */
	protected abstract void validateSignature(PrivateKey privateKey, byte[] signature) throws SignatureException;
	
	/**
	 * Generate a fulfillment object from the private key of the internal signature 
	 * and the signature itself.
	 * 
	 * @param privateKey The private key used to create the {@code signature}
	 * @param signature The signature generated using the provided {@code privateKey}.
	 * 
	 * @return The fulfillment generated from the provided key and signature.
	 * 
	 * @throws SignatureException
	 */
	protected abstract Fulfillment getFulfillment(PrivateKey privateKey, byte[] signature) throws SignatureException;
	
	/**
	 * Construct the public key used to verify the internal signature from the 
	 * fulfillment.
	 * 
	 * @param fulfillment
	 * @return
	 * @throws SignatureException
	 */
	protected abstract PublicKey getInternalPublicKey(Fulfillment fulfillment) throws SignatureException;

	/**
	 * Get the internal signature from the fulfillment.
	 * 
	 * @param fulfillment
	 * @return
	 * @throws SignatureException
	 */
	protected abstract byte[] getInternalSignature(Fulfillment fulfillment) throws SignatureException;

	@Override
	protected void engineUpdate(byte b) throws SignatureException {
		
		if(buffer != null) {
			//Delayed updates until we can get public key from fulfillment
			this.buffer.write(b);
		} else {
			this.internalSignature.update(b);
		}
	}

	@Override
	protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
		
		if(buffer != null) {
			//Delayed updates until we can get public key from fulfillment
			this.buffer.write(b, off, len);
		} else {
			this.internalSignature.update(b, off, len);
		}
	}

	@Override
	protected byte[] engineSign() throws SignatureException {
		
		byte[] internalSig = internalSignature.sign();		

		validateSignature(privateKey, internalSig);
		
		Fulfillment fulfillment = getFulfillment(privateKey, internalSig);
		
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		FulfillmentOerOutputStream stream = new FulfillmentOerOutputStream(buffer);
		
		try {
			stream.writeFulfillment(fulfillment);
			stream.flush();
			return buffer.toByteArray();
		} catch (IOException e) {
			throw new SignatureException(e);
		} catch (IllegalFulfillmentException e) {
			throw new SignatureException(e);
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
				throw new SignatureException(e);
			}
		}
		
	}
	
	@Override
	protected boolean engineVerify(byte[] oerEncodedFulfillment) throws SignatureException {
		
		//Decode fulfillment
		Fulfillment fulfillment;
		try {
			fulfillment = OerUtil.getFullfillment(oerEncodedFulfillment);
		} catch (IOException e) {
			throw new SignatureException(e);
		} catch (UnsupportedConditionException e) {
			throw new SignatureException(e);
		} catch (OerDecodingException e) {
			throw new SignatureException(e);
		} catch (IllegalFulfillmentException e) {
			throw new SignatureException(e);
		}
		
		//Fail fast if types are different
		//TODO: Is this an exception?
		if(fulfillment.getType() != this.getType())
			return false;
		
		//Get public key
		//TODO: Use KeyFactory
		PublicKey publicKey = getInternalPublicKey(fulfillment);
		byte[] signature = getInternalSignature(fulfillment);
				
		try {
			internalSignature.initVerify(publicKey);
		} catch (InvalidKeyException e) {
			throw new SignatureException(
					"The PublicKey derived from the fulfillment is invalid.", 
					e);
		}
		
		byte[] message = this.buffer.toByteArray();
		this.buffer.reset();
		
		internalSignature.update(message);
		
		return internalSignature.verify(signature);		
	}

	@Override
	protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
		throw new InvalidParameterException("Parameters are not supported.");
	}

	@Override
	protected Object engineGetParameter(String param) throws InvalidParameterException {
		throw new InvalidParameterException("Parameters are not supported.");
	}

}
