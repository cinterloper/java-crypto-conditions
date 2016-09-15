package org.interledger.cryptoconditions.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Convenience class for crypto functions
 * 
 * @author adrianhopebailie
 *
 */
public class Sha256Digest {
	
	public static final String ALGORITHM_NAME = "SHA-256";

	/**
	 * Get the Sha256 hash of a pre-image.
	 * 
	 * Convenience function which hides NoSuchAlgorithmException.
	 * 
	 * @param message
	 * @return SHA-256 digest of message
	 */
	public static byte[] getDigest(byte[] message) {
		try {
			MessageDigest digest = MessageDigest.getInstance(ALGORITHM_NAME);
			return digest.digest(message);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		}
	}
		
}
