package name.raess.abe.cp.objects;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import it.unisa.dia.gas.jpbc.Element;
import name.raess.abe.cp.CPabeSettings;
import name.raess.abe.cp.CPabeTools;

public class CPabePolicy {
	
	// this will be exported
	// attribute k
	public int k;
	// attribute string if leaf, otherwise null
	public String attribute;
	// true if leaf with value, otherwise false
	public boolean hasValue;
	// C and Cprime for every leaf attribute
	public Element cy;
	public Element cyPrime;
	/* array of children if this
	 * is a threshold gate 
     * it is 0 for leaves 
     * otherwise it is equal num */
	public CPabePolicy[] children;
	
	// only used during encryption -> not exported or saved 
	// polynomial for this policy
	public CPabePolynomial q;
	// only used during encryption -> not exported or saved 
	// is this policy satisfiable
	public boolean satisfiable;
	// only used during encryption -> not exported or saved 
	// index in parrent children arraylist 
	public int index;
	// only used during encryption -> not exported or saved 
	// satisfiable List
	public ArrayList<Integer> satisfiableList = new ArrayList<Integer>();
	// only used during encryption -> not exported or saved 
	// minimum leaves
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
		this.attribute = null;
		this.hasValue = false;
		this.children = new CPabePolicy[32];
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
			String attValue = this.attStringBinMaskValue(att, i++, binary.charAt(j));
			System.out.println("poly-attri: " + attValue);
			CPabePolicy child = new CPabePolicy(attValue);
			child.hasValue = true;
			// add to root node
			this.children[j] = child;
		}
	}
	
	// this is a policy tree with a value given as int
	// and a comparison given as LT (<) or GT (>)
	// For attValues from -2147483648 to 2147483647 inclusive.
	//
	public CPabePolicy(String att, int value, boolean isGreater) {
		this.attribute = null;
		this.hasValue = false;
		// this converts the int value into a string 
		String binaryTwoComplement = CPabeTools.convertToTwoComplement(value);
		// fuer den ausblick
		ArrayList<CPabePolicy> stack = new ArrayList<CPabePolicy>();
		String binary = Integer.toBinaryString(Math.abs(value));
		// if greater then zero and value is positive
		// first bit has to be zero	
		if(isGreater) {
			if(value >= 0) {
				// (first bit zero) && ((1 of the intermediate bits one) || (greater than absolute remainder))
				this.k = 2;
				this.children = new CPabePolicy[2];
				this.children[0] = new CPabePolicy(this.attStringBinMaskValue(att, att.length() + 1, '0'));
				this.children[1] = this.generatePolicy(att, binary, isGreater);
			}
			else {
				// (first bit zero) || ((first bit one) && (lesser than absolute remainder))
			}
		}
		else {
			if(value < 0) {
				// (first bit one) && ((1 of the intermediate bits zero) || (greater than remainder))
				this.k = 2;
				this.children = new CPabePolicy[2];				
				this.children[0] = new CPabePolicy(this.attStringBinMaskValue(att, att.length() + 1, '1'));
				this.children[1] = this.generatePolicy(att, binary, isGreater);
			}
			else {
				// (first bit one) || ((first bit zero) && (lesser than absolute remainder))
			}			
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

	private CPabePolicy generatePolicy(String att, String binary, boolean isGreater) {
		// TODO Auto-generated method stub
		return null;
	}

	// create a attribute string with value as a string bit mask 
	// covering everything but one single bit with *
	// i.e.: A:*******************************1
	public String attStringBinMaskValue(String att, int position, char value) {
		StringBuilder attributeValue = new StringBuilder(att + ":" + String.join("", Collections.nCopies(32, "*")));
		attributeValue.setCharAt(position, value);
		return attributeValue.toString();
	}
	
	// default ctor
	public CPabePolicy() {
		
	}

	// imports a byte[] policy
	public CPabePolicy(byte[] b64decode) {
		// TODO Auto-generated constructor stub
	}

	public String toString() {
		return this.toDetail(false);
	}

	public String toDetail(boolean showDetail) {
		String ret = "";
		if(this.k == 1 && !this.hasValue) {
			if(this.children != null) {
				ret += "(";
				for (int i = 0; i < this.children.length; i++) {
					ret += this.children[i].toString();
					if(i < this.children.length - 1) {
						ret += " or ";
					}
				}
				ret += ")";
			}
		}
		else if(this.k == 1 && this.hasValue) {
			if(this.hasValue) {
				if(showDetail) {
					ret = "[{" + this.attribute + "},{" + this.cy + "},{" + this.cyPrime + "}]";
				}
				else {
					ret = "[{" + this.attribute + "}]";
				}
			}
			else {
				ret = "[" + this.attribute + "]";
			}
		}
		else if(this.children != null && this.k == this.children.length) {
			ret = "( ";
			for (int i = 0; i < this.children.length; i++) {
				ret += this.children[i].toString();
				if(i < this.children.length - 1) {
					ret += " and ";
				}
			}
			ret += " )";
		}
		else if(this.children != null) {
			ret = "(" + this.k + "OF ";
			for (int i = 0; i < this.children.length; i++) {
				ret += this.children[i].toString();
				if(i < this.children.length - 1) {
					ret += ", ";
				}
			}
			ret += ")";
		}
		return ret;
	}
	
	public List<byte[]> toByteList() {
		List<byte[]> list = new ArrayList<byte[]>();
		byte[] hasValue = new byte[1];
		if(this.hasValue) {
			hasValue[0] = 1;
		}
		else {
			hasValue[0] = 0;
		}
		list.add(Integer.toString(this.k).getBytes());
		list.add(hasValue);
		// this is a leaf
		if(this.hasValue) {
			list.add(this.attribute.getBytes());
			list.add(this.cy.toBytes());
			list.add(this.cyPrime.toBytes());
		}
		// this is a threshold gate
		else {
			for(int x = 0;x < this.children.length; x++) {
				List<byte[]> child = this.children[x].toByteList();
				list.addAll(child);
			}
		}
		return list;
	}
/*
	public byte[] getBytes() {
		return this.toByteList().toString().getBytes();
		byte[] byteArray = new byte[list.size()];
		for (int index = 0; index < list.size(); index++) {
			byte[] h = (byte[]) list.get(index);
			byteArray[index] = h;
		}
		return byteArray;
	}*/
}