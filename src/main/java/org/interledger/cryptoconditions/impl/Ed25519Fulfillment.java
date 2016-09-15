package org.interledger.cryptoconditions.impl;

import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.crypto.Ed25519Signature;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;

/**
 * Implementation of an ED25519 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author earizon<enrique.arizon.benito@everis.com>
 * @author adrianhopebailie
 *
 */

public class Ed25519Fulfillment implements Fulfillment {

	private static final ConditionType TYPE = ConditionType.ED25519;
	private static EnumSet<FeatureSuite> FEATURES = EnumSet.of(
			FeatureSuite.SHA_256, 
			FeatureSuite.ED25519
		);
			
	public static final int PUBKEY_LENGTH = 32;
	public static final int SIGNATURE_LENGTH = 64;
	private static final int FULFILLMENT_LENGTH = PUBKEY_LENGTH + SIGNATURE_LENGTH;

	private EdDSAPublicKey publicKey;
	private byte[] signature;

	@Override
	public ConditionType getType() {
		return TYPE;
	}

	public EdDSAPublicKey getPublicKey() {
		return this.publicKey;
	}
		
	public void setPublicKey(EdDSAPublicKey publicKey) {
		this.publicKey = publicKey;
	}
	
	public byte[] getSignature() {
		return this.signature;
	}
	
	public void setSignature(byte[] signature) {
		this.signature = signature;
	}
	
	@Override
	public Condition computeCondition() {
		if (getPublicKey() == null) {
			throw new NullPointerException("Public Key is null.");
		}
		
		try {
			return new ConditionImpl(TYPE, FEATURES, getPublicKey().getEncoded() , FULFILLMENT_LENGTH);
		} catch (Exception e) {
			throw new RuntimeException(e.toString(), e);
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
			return Ed25519Signature.verify(getPublicKey(), message, getSignature());
		} catch (Exception e) {
			throw new RuntimeException(e.toString(), e);
		}
	}

	public static Ed25519Fulfillment fromPrivateKeyAndMessage(EdDSAPrivateKey privateKey, byte[] message) {
		byte[] signature;
		try {
			signature = Ed25519Signature.sign(privateKey, message);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		Ed25519Fulfillment f = new Ed25519Fulfillment();
		f.setPublicKey(Ed25519Signature.getPublicKeyFromPrivateKey(privateKey));
		f.setSignature(signature);
		return f;
		
	}

}
