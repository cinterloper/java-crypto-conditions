package org.interledger.cryptoconditions.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.encoding.ByteArrayOutputStreamPredictor;
import org.interledger.cryptoconditions.encoding.ConditionOutputStream;
import org.interledger.cryptoconditions.encoding.FulfillmentOutputStream;
import org.interledger.cryptoconditions.encoding.OerOutputStream;
import org.interledger.cryptoconditions.encoding.OerUtil;

public class ThresholdSHA256Fulfillment implements Fulfillment {

	private static ConditionType TYPE = ConditionType.THRESHOLD_SHA256;
	private static EnumSet<FeatureSuite> FEATURES = EnumSet.of(
			FeatureSuite.SHA_256, 
			FeatureSuite.THRESHOLD
		);

	
    private class OrderableByteBuffer implements Comparable<OrderableByteBuffer> {
        byte[] buffer;
        public OrderableByteBuffer(byte[] buffer){
            this.buffer = buffer;
        }
        
        @Override
        public int compareTo(OrderableByteBuffer another) {
            if (this.buffer.length != another.buffer.length){
                return this.buffer.length - another.buffer.length;
            }
            // REF: http://stackoverflow.com/questions/5108091/java-comparator-for-byte-array-lexicographic
            // TODO: Check that this match the JS code Buffer.compare(a, b)
            int lexicoComparation = 0; // FIXME Compare lexicographically
            byte[]  left  = this.buffer, 
                    right = another.buffer;
            for (int idx = 0; idx < this.buffer.length; idx++) {
                int a = (left[idx] & 0xff);
                int b = (right[idx] & 0xff);
                if (a != b) { lexicoComparation = a - b; break; }
            }
            return lexicoComparation;
        }
    }
    
    private class WeightedFulfillment implements Comparable<WeightedFulfillment> {
        final int weight;
        final Fulfillment subff;
        final byte[] conditionFingerprint; // FIXME TODO: Replace with OrderableByteBuffer
        int idx = -1;
        private WeightedFulfillment(int weight, Fulfillment subfulfillment) {
            this.weight = weight;
            this.subff = subfulfillment;
            conditionFingerprint = this.subff.computeCondition().getFingerprint();
        }
        
        void setIdx(int idx) { this.idx = idx; }
        
        int getSize() {
            return OerUtil.getOerEncodedFulfillment(this.subff).length;
        }

        int getOmitSize() {
            return OerUtil.getOerEncodedCondition(this.subff.computeCondition()).length;
        }

        @Override
        public int compareTo(WeightedFulfillment another) {
            if (this.conditionFingerprint.length != another.conditionFingerprint.length){
                return this.conditionFingerprint.length - another.conditionFingerprint.length;
            }
            // REF: http://stackoverflow.com/questions/5108091/java-comparator-for-byte-array-lexicographic
            // TODO: Check that this match the JS code Buffer.compare(a, b)
            int lexicoComparation = 0; // FIXME Compare lexicographically
            byte[]  left  = this.conditionFingerprint, 
                    right = another.conditionFingerprint;
            for (int idx = 0; idx < this.conditionFingerprint.length; idx++) {
                int a = (left[idx] & 0xff);
                int b = (right[idx] & 0xff);
                if (a != b) { lexicoComparation = a - b; break; }
            }
            return lexicoComparation;
        }
    }

    private class WeightAndSize implements Comparable<WeightAndSize> {
        public final int  weight;
        public final int  size;
        private WeightAndSize(int weight, int size) {
        	this.weight = weight;
        	this.size   = size;
        }

        @Override
        public int compareTo(WeightAndSize another) {
            return this.weight - another.weight;
        }
    }
       
    private final long threshold; // FIXME Check that it's smaller than 2<<31 since it must be converted to int.
    private final List<WeightedFulfillment> subfulfillments;

    public ThresholdSHA256Fulfillment(ConditionType type, byte[] payload, 
            int threshold, List<Integer>weight_l, List<Fulfillment> ff_l){
        if (weight_l.size() != ff_l.size()) {
            throw new RuntimeException("Can't zip weight_l && ff_l. Size differs ");
        }
        List<WeightedFulfillment> wff_l = new java.util.ArrayList<WeightedFulfillment>();
        for (int idx=0; idx< weight_l.size(); idx++) {
            wff_l.add(new WeightedFulfillment(weight_l.get(idx), ff_l.get(idx)));
        }
        this.threshold = threshold;
        Collections.sort(wff_l); // sort.
        for (int idx=0; idx<wff_l.size(); idx++) { wff_l.get(idx).setIdx(idx); }
        this.subfulfillments = wff_l;
        
        throw new RuntimeException("FIXME Implement?");
    }
    
	@Override
	public ConditionType getType() {
		return TYPE;
	}
    
    @Override
    public Condition computeCondition() {
    	
        //writeHashPayload (hasher) /* Produce the contents of the condition hash. */ {
        //  const subconditions = this.subconditions // Serialize each subcondition with weight
        //        .map((c) => { writer.writeVarUInt(c.weight),  writer.write(getConditionBinary()) })
        //  hasher.writeUInt32(this.threshold)
        //  hasher.writeVarUInt(sortedSubconditions.length)
        //  sortedSubconditions.forEach((c) => hasher.write(c))
        //}

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] fingerprint;
        ConditionOutputStream cos = new ConditionOutputStream(baos);
        try {
            cos.write32BitUInt((long)this.threshold);
            cos.writeVarUInt(this.subfulfillments.size());
            for (int idx = 0; idx < this.subfulfillments.size(); idx++) {
            	WeightedFulfillment w_ff = this.subfulfillments.get(idx);
                cos.writeVarUInt(w_ff.weight);
                cos.writeCondition(w_ff.subff.computeCondition());
            }
            fingerprint = baos.toByteArray();
        } catch(Exception e){
            throw new RuntimeException(e.toString(), e);
        } finally {
            try {
				cos.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
        }

    	int fulfillmentMaxLength = this.calculateMaxFulfillmentLength();
        return new ConditionImpl(
                ConditionType.THRESHOLD_SHA256,
                getFeatureSuiteSet(),
                fingerprint,
                fulfillmentMaxLength);
    }

    @Override
    public boolean validate(byte[] message) {
        //validate (message) {
        //  const fulfillments = this.subconditions.filter((cond) => cond.type === FULFILLMENT)
        //
        //  let minWeight = Infinity // Find total weight and smallest individual weight
        //  const totalWeight = fulfillments.reduce((total, cond) => {
        //        minWeight = Math.min(minWeight, cond.weight)
        //        return total + cond.weight
        //  }, 0)
        //
        //  if (totalWeight < this.threshold) throw Error('Threshold not met')
        //
        //  // the set must be minimal, there mustn't be any fulfillments we could take out
        //  if (this.threshold + minWeight <= totalWeight) 
        //        throw new Error('Fulfillment is not minimal')
        //
        //  return fulfillments.every((f) => f.body.validate(message))
        //}
        throw new RuntimeException("not implemented"); // FIXME TODO
    }

    private EnumSet<FeatureSuite> getFeatureSuiteSet() {
        final EnumSet<FeatureSuite> BASE_FEATURES = EnumSet.of(
                FeatureSuite.SHA_256,
                FeatureSuite.THRESHOLD );
        EnumSet<FeatureSuite> result = BASE_FEATURES;
        for (WeightedFulfillment ff : subfulfillments ){
            EnumSet<FeatureSuite> childFeatures = ff.subff.computeCondition().getFeatures();
            for (FeatureSuite fs : childFeatures) {
                if (! result.contains(fs)) { result.add(fs); }
            }
        }
        return result;
    }

    /** Calculate the worst case length of a set of conditions.
    * longest possible length for valid, minimal set of subconditions. */
    static int calculateWorstCaseLength (long threshold, List<WeightAndSize> WeightAndSize_l, int idx) {
         if (threshold <= 0) return 0;
         if (idx > WeightAndSize_l.size()) return -2^31; /* FIXME: IN JS -Infinity */
         WeightAndSize ws = WeightAndSize_l.get(idx);
         idx++;
         return Math.max(
             ws.size+calculateWorstCaseLength(threshold-ws.weight,WeightAndSize_l,idx)  ,
                     calculateWorstCaseLength(threshold           ,WeightAndSize_l,idx) );
    }

    static int predictSubconditionLength(Condition cond) {
        return OerUtil.getOerEncodedCondition(cond).length; 
    }

    static int predictSubfulfillmentLength(Fulfillment ff) {
        int fulfillmentLength = ff.computeCondition().getMaxFulfillmentLength();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OerOutputStream cos = new OerOutputStream(baos);
        try {
            cos.write16BitUInt(0 /* type Undefined */);
            byte[] bytes = new byte[fulfillmentLength];
            java.util.Arrays.fill( bytes, (byte) 0 );

            cos.writeOctetString(bytes);
            int result = baos.size();
            return result;
        }catch(Exception e) {
            throw new RuntimeException(e.toString(), e);
        } finally {
            try {
				cos.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
        }
    }

    /*
     * Calculates the longest possible fulfillment length.
     * In a threshold condition, the maximum length of the fulfillment depends on
     * the maximum lengths of the fulfillments of the subconditions. However,
     * usually not all subconditions must be fulfilled in order to meet the
     * threshold.
     * Consequently, this method relies on an algorithm to determine which
     * combination of fulfillments, where no fulfillment can be left out, results
     * in the largest total fulfillment size. 
     */
    private int calculateMaxFulfillmentLength () { // Calculate length of longest fulfillments
        int totalConditionLength = 0;

        List<WeightAndSize> WeightAndSize_l = new java.util.ArrayList<WeightAndSize>();
        for (int idx=0; idx < this.subfulfillments.size(); idx++) {
            WeightedFulfillment wfulf = this.subfulfillments.get(idx);
            Condition cond = this.subfulfillments.get(idx).subff.computeCondition();
            int conditionLength   = ThresholdSHA256Fulfillment.predictSubconditionLength(cond);
            int fulfillmentLength = ThresholdSHA256Fulfillment.predictSubfulfillmentLength(wfulf.subff);
            totalConditionLength += conditionLength;
            WeightAndSize_l.add(
                new WeightAndSize(wfulf.weight, fulfillmentLength - conditionLength));
        }
        Collections.sort(WeightAndSize_l);
        int worstCaseFulfillmentsLength = totalConditionLength +
            ThresholdSHA256Fulfillment.calculateWorstCaseLength( this.threshold, WeightAndSize_l, /*idx*/0);
        if (worstCaseFulfillmentsLength < 1<<30 /* FIXME In JS: -Infinity */) {
           throw new RuntimeException("Insufficient subconditions/weights to meet the threshold");
        }
        // Calculate resulting total maximum fulfillment size
        ByteArrayOutputStreamPredictor buffer = new ByteArrayOutputStreamPredictor();
        FulfillmentOutputStream ffos = new FulfillmentOutputStream(buffer);
        try {
            ffos.write32BitUInt(this.threshold);
            ffos.writeVarUInt(this.subfulfillments.size());
            for (int idx=0; idx< this.subfulfillments.size() ; idx++) {
                ffos.write8BitUInt(0 /*FIXME empty presence bitmask in JS*/);
                WeightedFulfillment wff = this.subfulfillments.get(idx);
                if (wff.weight != 1) ffos.write32BitUInt(wff.weight);
            }
            // Represents the sum of CONDITION/FULFILLMENT values
            // FIXME: predictor.skip(worstCaseFulfillmentsLength)
            int result = buffer.size();
            return result;
        } catch(Exception e) {
            throw new RuntimeException(e.toString(), e);
        } finally { 
            try {
				ffos.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
        }
    }

    //selects smallest combination of fulfillments meeting a threshold.
    static class calcSmallestFFSetState { // TODO:(0) What static means for inner classes??
        int index = 0;
        int size  = 0;
        Set<Integer> set = new HashSet<Integer>();
        calcSmallestFFSetState(int index, int size, Set<Integer> set) {
            this.index = index;
            this.size  = size;
            this.set   = set;
        }
    }

    static calcSmallestFFSetState calculateSmallestValidFulfillmentSet (long threshold, List<WeightedFulfillment> ff_l, calcSmallestFFSetState state) {
        if (threshold < 0) { return state; }
        if (state.index > ff_l.size()) { state.size = 2^31; /* FIXME TODO In JS Infinity */ }
        WeightedFulfillment nextFF = ff_l.get(state.index);

        Set<Integer> set_with_next = new HashSet<Integer>(state.set);
                     set_with_next.add(nextFF.idx);
        calcSmallestFFSetState with_next = ThresholdSHA256Fulfillment.calculateSmallestValidFulfillmentSet(
                threshold  - nextFF.weight, ff_l, 
                new ThresholdSHA256Fulfillment.calcSmallestFFSetState(state.size + nextFF.getSize(), state.index+1, set_with_next) 
                );
        calcSmallestFFSetState without_next = ThresholdSHA256Fulfillment.calculateSmallestValidFulfillmentSet(
                threshold , ff_l, 
                new ThresholdSHA256Fulfillment.calcSmallestFFSetState(state.size + nextFF.getOmitSize(), state.index+1, state.set) 
                );
        return (with_next.size < without_next.size) ? with_next : without_next;
    }

    private byte[] writePayload() {
        calcSmallestFFSetState smallestFFSet = ThresholdSHA256Fulfillment.calculateSmallestValidFulfillmentSet(
            this.threshold, this.subfulfillments, new calcSmallestFFSetState(0, 0, new HashSet<Integer>()));
    
        List<Condition> optimizedConditions = new ArrayList<Condition>();// Take minimum set of fulfillments and turn rest into conditions
        for (int idx=0; idx<this.subfulfillments.size(); idx++) {
            WeightedFulfillment subff = this.subfulfillments.get(idx);
            if (! smallestFFSet.set.contains(subff.idx) ) {
                optimizedConditions.add(subff.subff.computeCondition());
            }
        }

        List<OrderableByteBuffer> sortedSubconditions = new ArrayList<OrderableByteBuffer>();

        for (int idx=0; idx<this.subfulfillments.size(); idx++) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            OerOutputStream cos = new OerOutputStream(baos);
            try {
                WeightedFulfillment wff = this.subfulfillments.get(idx);
                cos.writeVarUInt(wff.weight);
                cos.writeOctetString(OerUtil.getOerEncodedFulfillment(wff.subff));
                sortedSubconditions.add(new OrderableByteBuffer(baos.toByteArray()));
            }catch(Exception e) {
                throw new RuntimeException(e.toString(), e);
            } finally {
                try {
					cos.close();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
            }
        }
        Collections.sort(sortedSubconditions);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OerOutputStream cos = new OerOutputStream(baos);
        try {
            cos.writeVarUInt((int)this.threshold);
            cos.writeVarUInt(sortedSubconditions.size());
            for (int idx=0; idx<sortedSubconditions.size(); idx++) {
                // FIXME: IN JS this loop looks like:
                //   sortedSubconditions.forEach(writer.write.bind(writer))
                OrderableByteBuffer buf = sortedSubconditions.get(idx);
                cos.writeOctetString(buf.buffer);
            }
            byte[] result = baos.toByteArray();
            return result;
        }catch(Exception e) {
            throw new RuntimeException(e.toString(), e);
        } finally {
            try {
				cos.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
        }

    }

}