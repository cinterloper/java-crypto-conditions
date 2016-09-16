package org.interledger.cryptoconditions.encoding;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.IllegalFulfillmentException;

public class OerUtil {
	
	/**
	 * Convenience function for getting the binary encoding of a Fulfillment
	 * 
	 * @param condition
	 * @return The OER encoded condition
	 */
	public static byte[] getOerEncodedCondition(Condition condition)
	{
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ConditionOutputStream stream = new ConditionOutputStream(buffer);
		
		try {
			stream.writeCondition(condition);
			stream.flush();
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		return buffer.toByteArray();
	}
	
	/**
	 * Convenience function for getting the binary encoding of a Fulfillment
	 * 
	 * Hides the potential IllegalFulfillmentException behind a RuntimeException
	 * 
	 * @param fulfillment
	 * @return The OER encoded fulfillment
	 * @throws RuntimeException if the Fulfillment is not ready to be encoded.
	 */
	public static byte[] getOerEncodedFulfillment(Fulfillment fulfillment)
	{
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		FulfillmentOutputStream stream = new FulfillmentOutputStream(buffer);
		
		try {
			stream.writeFulfillment(fulfillment);
			stream.flush();
		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (IllegalFulfillmentException e) {
			throw new RuntimeException(e);
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		return buffer.toByteArray();
		
	}

}
