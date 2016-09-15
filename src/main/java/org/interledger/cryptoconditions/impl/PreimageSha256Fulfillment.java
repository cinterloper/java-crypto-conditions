package org.interledger.cryptoconditions.impl;

import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.crypto.Sha256Digest;

/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class PreimageSha256Fulfillment implements Fulfillment{
    
	private static EnumSet<FeatureSuite> FEATURES = EnumSet.of(
			FeatureSuite.SHA_256, 
			FeatureSuite.PREIMAGE
		);
	
	private byte[] preimage = null;

	public PreimageSha256Fulfillment() {
	}

	@Override
	public ConditionType getType() {
		return ConditionType.PREIMAGE_SHA256;
	}

    public byte[] getPreimage() {
        return this.preimage;
    }

    public void setPreimage(byte[] preimage) {
    	this.preimage = preimage;
    }

	@Override
	public Condition computeCondition() {
		
		if(getPreimage() == null) {
			throw new NullPointerException("Preimage is null.");
		}
		
		byte[] fingerprint = Sha256Digest.getDigest(getPreimage());
		int maxFulfillmentLength = getPreimage().length;
		
		return new ConditionImpl(
				ConditionType.PREIMAGE_SHA256, 
				FEATURES, 
				fingerprint, 
				maxFulfillmentLength);
	}
	
	/**
	 * Validate this fulfillment.
	 *
	 * For a SHA256 hashlock fulfillment, successful parsing implies that the
	 * fulfillment is valid, so this method is a no-op.
	 *
	 * @param {byte[]} Message (ignored in this condition type)
	 * @return {boolean} Validation result
	 */
	@Override
	public boolean validate(byte[] message) {
		return true;
	}
	
    public static PreimageSha256Fulfillment fromPreimage(byte[] preimage){
    	PreimageSha256Fulfillment f = new PreimageSha256Fulfillment();
    	f.setPreimage(preimage);
        return f;
    }

}
