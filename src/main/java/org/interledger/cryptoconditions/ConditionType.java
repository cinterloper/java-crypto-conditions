package org.interledger.cryptoconditions;

import java.util.EnumSet;

/**
 * Enumeration of crypto-condition types
 * 
 * @author adrianhopebailie
 *
 */
public enum ConditionType {
	
	PREIMAGE_SHA256(0),
	PREFIX_SHA256(1),
	THRESHOLD_SHA256(2),
	RSA_SHA256(3),
	ED25519(4);

	
	private final int typeCode;
	
	ConditionType(int typeCode)
	{
		this.typeCode = typeCode;
	}
	
	/**
	 * Get the ASN.1 enum code for this type
	 * 
	 * @return the ASN.1 enumeration number
	 */
	public int getTypeCode() {
		return this.typeCode;
	}
		
	public static ConditionType valueOf(int typeCode) {
		
		for (ConditionType conditionType : EnumSet.allOf(ConditionType.class)) {
			if(typeCode == conditionType.typeCode)
				return conditionType;
		}
		
		throw new IllegalArgumentException("Invalid Condition Type code.");		
	}

}
