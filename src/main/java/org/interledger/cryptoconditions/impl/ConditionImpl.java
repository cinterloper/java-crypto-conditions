package org.interledger.cryptoconditions.impl;

import java.util.Arrays;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;

/**
 * Convenience class used to generate a new immutable 
 * condition object
 * 
 * @author adrianhopebailie
 */
class ConditionImpl implements Condition {

	// Condition Interface related members 
	private final ConditionType type;
	private final EnumSet<FeatureSuite> features;
	private final byte[] fingerprint;
	private final int maxFulfillmentLength;

	// URISerializable Interface related members
	//TODO - Move to writer
	//private static final String CONDITION_REGEX = "^cc:([1-9a-f][0-9a-f]{0,3}|0):[1-9a-f][0-9a-f]{0,15}:[a-zA-Z0-9_-]{0,86}:([1-9][0-9]{0,17}|0)$";
	//private static final java.util.regex.Pattern p = java.util.regex.Pattern.compile(CONDITION_REGEX);
		
	public ConditionImpl(ConditionType type, EnumSet<FeatureSuite> features, 
			byte[] fingerprint, int maxFulfillmentLength) {

		if (type == null) 
			throw new IllegalArgumentException("Type cannot be null.");
		
		if (fingerprint == null) 
			throw new IllegalArgumentException("Fingerprint cannot be null.");
		
		if (features == null || features.isEmpty()) 
			throw new IllegalArgumentException("Features cannot be null or empty.");
		
		if (maxFulfillmentLength < 0) 
			throw new IllegalArgumentException("MaxFulfillmentLength can't be negative.");
		
		this.type = type;
		this.fingerprint = fingerprint;
		this.features = features;
		this.maxFulfillmentLength = maxFulfillmentLength;
	}

	@Override
	public ConditionType getType() {
		return this.type;
	}
	
	@Override
	public EnumSet<FeatureSuite> getFeatures(){
		return EnumSet.copyOf(this.features);
	}
	

	@Override
	public byte[] getFingerprint(){
		return Arrays.copyOf(this.fingerprint, this.fingerprint.length);
	}

	@Override
	public int getMaxFulfillmentLength() {
		return this.maxFulfillmentLength;
	}
		
}