package name.raess.abe.cp.objects;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import it.unisa.dia.gas.jpbc.Element;
import name.raess.abe.cp.CPabeSettings;
import name.raess.abe.cp.CPabeTools;

public class CPabePolicy {
	/* attribute k */
	public int k;
	/* attribute string if leaf, otherwise null */
	public String attribute;
	/* true if leaf with value, otherwise false */
	public boolean hasValue;
	// C and Cprime are a part of this policy
	public Element cy;
	public Element cy_Prime;
	/* array of children if this
	 * is a threshold gate 
     * it is 0 for leaves 
     * otherwise it is equal num */
	public CPabePolicy[] children;
	/* used during encryption */
	public CPabePolynomial q;
	/* used during decryption */
	public boolean satisfiable;
	/* index in parrent children arraylist */
	public int index;
	public ArrayList<Integer> satisfiableList = new ArrayList<Integer>();
	public int minLeaves;
	
	// this is a threshhold gate
	public CPabePolicy(int k, int n) {
		this.k = k;
		this.hasValue = false;
		this.attribute = null;
		this.children = new CPabePolicy[n];
	}
	
	// this is a threshhold gate
	public CPabePolicy(int k) {
		this.k = k;
		this.hasValue = false;
		this.attribute = null;
		this.children = new CPabePolicy[k];
	}	
	
	// this is an policy attribute without a value
	public CPabePolicy(String s) {
		this.k = 1;
		this.hasValue = false;
		this.attribute = s;
		this.children = null;
	}
	
	// this is a policy tree with a value given as int
	// For int, from -2147483648 to 2147483647 inclusive, 
	// converted to bitmask with 32 bits -> i.e. 32 children
	public CPabePolicy(String att, int value) {
		this.k = 32;
		this.attribute = att;
		this.hasValue = true;
		this.children = new CPabePolicy[32];
		// this generates a string
		// of length 32 filled with *
		String bitMask = String.join("", Collections.nCopies(32, "*"));
		// this converts the int value in a string 
		String binary = CPabeTools.convertToTwoComplement(value);
		// counter for loop over binary string
		int i = att.length() + 1;
		// loop over bitMask beginning at 
		// length of attribute name +1 (because of :)
		// for 32 bits length
		for(int j = 0; j < 32; j++) {
			/* create attribute string
			 * i.e. for A=5 create:
			 * A:0*******************************
			 * A:*0******************************
			 * A:**0*****************************
			 * A:***0****************************
			 * A:****0***************************
			 * A:*****0**************************
			 * A:******0*************************
			 * A:*******0************************
			 * A:********0***********************
			 * A:*********0**********************
			 * A:**********0*********************
			 * A:***********0********************
			 * A:************0*******************
			 * A:*************0******************
			 * A:**************0*****************
			 * A:***************0****************
			 * A:****************0***************
			 * A:*****************0**************
			 * A:******************0*************
			 * A:*******************0************
			 * A:********************0***********
			 * A:*********************0**********
			 * A:**********************0*********
			 * A:***********************0********
			 * A:************************0*******
			 * A:*************************0******
			 * A:**************************0*****
			 * A:***************************0****
			 * A:****************************0***
			 * A:*****************************1**
			 * A:******************************0*
			 * A:*******************************1
			 */
			// create bitmask 
			// i.e. A:********************************
			StringBuilder attributeValue = new StringBuilder(att + ":" + bitMask);
			// replace char at position i with value from binary string using counter j
			// i.e. A:*******************************1 
			attributeValue.setCharAt(i++, binary.charAt(j));
			// create attribute child using this string
			System.out.println("poly-attri: " + attributeValue.toString());
			CPabePolicy child = new CPabePolicy(attributeValue.toString());
			child.hasValue = true;
			// add to root node
			this.children[j] = child;
		}
	}
	
	// this is a policy tree with a value given as int
	// and a comparison given as LT (<) or GT (>)
	// For int, from -2147483648 to 2147483647 inclusive.
	//
	public CPabePolicy(String att, int attValue, boolean isGreater) {
		this.attribute = att;
		this.hasValue = true;
		int k = 0;
		// this converts the int value into a string 
		String binaryTwoComplement = CPabeTools.convertToTwoComplement(attValue);
		ArrayList<CPabePolicy> stack = new ArrayList<CPabePolicy>();
		String binary = Integer.toBinaryString(Math.abs(attValue));
		// if greater then and value is positive
		if(isGreater) {
			
		}
		// if less then and value is negative
		// first bit has to be one		
		else {
			
		}
		// otherwise we don't know the sign
		
		/*
		// leading 0s
		String binaryMask = String.format("%31s", binaryString).replace(' ', '0');
		// set 0 values
		for(int j = 0; j < gtc; j++) {
				StringBuilder attributeValue = new StringBuilder(att + ":" + bitMask);
				attributeValue.setCharAt(att.length() + 1 + j, binaryMask.charAt(j));
				// create attribute child using this string
				System.out.println(attributeValue.toString());
				CPabePolicy child = new CPabePolicy(attributeValue.toString());
				child.hasValue = true;
				// add to root node
				this.children[j] = child;
			}
			StringBuilder attributeValue = new StringBuilder(att + ":" + bitMask);
			attributeValue.setCharAt(att.length() + 1 + gtc, '1');
			// create attribute child using this string
			System.out.println(attributeValue.toString());
			CPabePolicy currentOnechild = new CPabePolicy(attributeValue.toString());
			currentOnechild.hasValue = true;
			// and add to root node
			this.children[gtc] = currentOnechild;
			// now add the rest of the binary string
			CPabePolicy child = new CPabePolicy(att, Integer.parseInt(binaryString.substring(1)), operation);
			child.hasValue = true;
			// add to root node
			this.children[gtc] = child;
			*/
		this.k = stack.size();
		this.children = stack.toArray(new CPabePolicy[stack.size()]);
	}
	
	// default ctor
	public CPabePolicy() {
		
	}

	public String toString() {
		return this.toDetail(false);
	}

	public String toDetail(boolean showDetail) {
		if(this.k == 1 && this.attribute == null) {
			String ret = "";
			if(this.children != null) {
				ret += "(";
				for (int i = 0; i < this.children.length; i++) {
					ret += this.children[i].toString();
					if(i < this.children.length - 1) {
						ret += " || ";
					}
				}
				ret += ")";
			}
			return ret;
		}
		else if(this.k == 1) {
			if(this.hasValue) {
				if(showDetail) {
					return "[{" + this.attribute + "},{" + this.cy + "},{" + this.cy_Prime + "}]";
				}
				else {
					return "[{" + this.attribute + "}]";
				}
			}
			else {
				return "[" + this.attribute + "]";
			}
		}
		else if(this.k == this.children.length) {
			String ret = "( ";
			for (int i = 0; i < this.children.length; i++) {
				ret += this.children[i].toString();
				if(i < this.children.length - 1) {
					ret += " && ";
				}
			}
			ret += " )";
			return ret;
		}
		else {
			String ret = "(" + this.k + "OF ";
			for (int i = 0; i < this.children.length; i++) {
				ret += this.children[i].toString();
				if(i < this.children.length - 1) {
					ret += ", ";
				}
			}
			ret += ")";
			return ret;
		}
	}
}