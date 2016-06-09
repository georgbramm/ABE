package name.raess.abe.cp.objects;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import it.unisa.dia.gas.jpbc.Element;

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
	}	
	
	// this is an attribute without a value
	public CPabePolicy(String s) {
		this.k = 1;
		this.hasValue = false;
		this.attribute = s;
		this.children = null;
	}	
	// this is an attribute with a value given as int
	// For int, from -2147483648 to 2147483647 inclusive, 
	// converted to bitmask with 32 bits -> i.e. 32 children
	public CPabePolicy(String att, int value) {
		this.k = 32;
		this.attribute = att;
		this.children = new CPabePolicy[32];
		// this generates a string
		// of length 32 filled with *
		String bitMask = String.join("", Collections.nCopies(32, "*"));
		// this converts the int value in a string 
		String binary = Integer.toBinaryString(value);
		// and left pads it up to a length of 32 with zeros
		binary = String.format("%32s", binary).replace(' ', '0');
		// counter for loop over binary string
		int j = 0;
		// loop over bitMask beginning at 
		// length of attribute name +1 (because of :)
		// for 32 bits length
		for(int i = att.length() + 1; i < 32 + 1 + att.length(); i++) {
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
			attributeValue.setCharAt(i, binary.charAt(j++));
			// create attribute child using this string
			CPabePolicy child = new CPabePolicy(attributeValue.toString());
			child.hasValue = true;
			// add to root node
			this.children[j] = child;
		}
	}
	
	public CPabePolicy() {
		
	}
	
	public String toString() {
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
				return "[{" + this.attribute + "},{" + this.cy + "},{" + this.cy_Prime + "}]";
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