package org.interledger.cryptoconditions.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.crypto.Sha256Digest;
import org.interledger.cryptoconditions.encoding.ConditionOutputStream;

/**
 * Implementation of a PREFIX-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class PrefixSha256Fulfillment implements Fulfillment {


	private static ConditionType TYPE = ConditionType.PREFIX_SHA256;
	private static EnumSet<FeatureSuite> FEATURES = EnumSet.of(
			FeatureSuite.SHA_256, 
			FeatureSuite.PREFIX
		);

	private byte[] prefix;
	private Fulfillment subfulfillment;
	
	public byte[] getPrefix() {
		return prefix;
	}
	
	public void setPrefix(byte[] prefix) {
		this.prefix = prefix;
	}

	public Fulfillment getSubFulfillment()
	{
		return subfulfillment;
	}
	
	public void setSubFulfillment(Fulfillment subfulfillment) {
		this.subfulfillment = subfulfillment;
	}
	
	@Override
	public ConditionType getType() {
		return TYPE;
	}

	@Override
	public Condition computeCondition() {
		Condition subcondition = subfulfillment.computeCondition();
		
		EnumSet<FeatureSuite> features = subcondition.getFeatures();
		features.addAll(FEATURES);

		byte[] fingerprint = Sha256Digest.getDigest(
				calculateFingerPrintContent(
					prefix, 
					subcondition
				)
			);
		
		int maxFulfillmentLength = calculateMaxFulfillmentLength(
				prefix, 
				subcondition
			);
		
		return new ConditionImpl(
				ConditionType.PREFIX_SHA256, 
				features, 
				fingerprint, 
				maxFulfillmentLength);
	}
	
	private byte[] calculateFingerPrintContent(byte[] prefix, Condition subcondition)
	{
		
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ConditionOutputStream stream = new ConditionOutputStream(buffer);
		
		try {
			stream.writeOctetString(prefix);
			stream.writeCondition(subcondition);
			stream.flush();
			return buffer.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
				stream.close();
		}
	}
	
	private int calculateMaxFulfillmentLength(byte[] prefix, Condition subcondition)
	{
		int length = prefix.length;
		if(length < 128)
		{
			length = length + 1;
		} else if(length <= 255) {
			length = length + 2;
		} else if (length <= 65535) {
			length = length + 3;
		} else if (length <= 16777215){
			length = length + 4;
		} else {
			throw new IllegalArgumentException("Field lengths of greater than 16777215 are not supported.");
		}
		return length + subcondition.getMaxFulfillmentLength();
	}

	@Override
	public boolean validate(byte[] message) {
		
		if (this.prefix == null)
			throw new NullPointerException("Prefix is null.");
		
		if (this.subfulfillment == null)
			throw new NullPointerException("Subfulfillment is null.");
		
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		try {
			outputStream.write( this.prefix);
			outputStream.write( message );
		} catch (IOException e) {
			throw new RuntimeException(e.toString());
		}
		
		return this.subfulfillment.validate(outputStream.toByteArray());
	}
	
	public static PrefixSha256Fulfillment fromPrefixAndFulfillment(byte[] prefix, Fulfillment subfulfillment) {
		
		PrefixSha256Fulfillment f = new PrefixSha256Fulfillment();
		f.setPrefix(prefix);
		f.setSubFulfillment(subfulfillment);
		return f;
	}

}
