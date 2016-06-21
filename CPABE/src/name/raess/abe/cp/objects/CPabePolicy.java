package name.raess.abe.cp.objects;

import java.util.ArrayList;
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
	// this will not be exported
	// and is used only during encryption 
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
	// default ctor
	public CPabePolicy() {
		
	}	
	// a (k, n)-threshhold gate ctor
	// i.e.: 
	// OR	->	(1, n) 
	// XOF	->	(X, n)
	public CPabePolicy(int k, int n) {
		this.k = k;
		this.hasValue = false;
		this.attribute = null;
		this.children = new CPabePolicy[n];
	}
	// a (k, k)-threshhold gate ctor
	// i.e.: 
	// AND	->	(k, k) 
	public CPabePolicy(int k) {
		this.k = k;
		this.hasValue = false;
		this.attribute = null;
		this.children = new CPabePolicy[k];
	}	
	// this is an attribute without a value
	public CPabePolicy(String attValue) {
		this.k = 1;
		this.hasValue = false;
		this.attribute = attValue;
		this.children = null;
	}
	// this is part of an attribute with a value
	public CPabePolicy(String attValue, boolean b) {
		this.k = 1;
		this.hasValue = b;
		this.attribute = attValue;
		this.children = null;
	}
	// this is an attribute with a value given as int.
	// For value, from -2147483648 to 2147483647 inclusive, 
	// converted to bitmask with 32 bits -> i.e. 32 children
	public CPabePolicy(String att, int value) {
		this.k = 32;
		this.attribute = null;
		this.hasValue = false;
		this.children = new CPabePolicy[32];
		// this converts the int value in a string 
		String binary = CPabeTools.convertToTwoComplement(value);
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
			String attValue = this.attStringBinMaskValue(att, j, binary.charAt(j));
			CPabePolicy child = new CPabePolicy(attValue, true);
			// add to root node
			this.children[j] = child;
		}
	}
	// this is an attribute with a value given as int.
	// together with a comparison given as LT (<) or GT (>)
	// resulting in a policy represeting that inequation
	// For value from -2147483648 to 2147483647 inclusive.
	public CPabePolicy(String att, int value, boolean isGreater) {
		String complement = CPabeTools.convertToTwoComplement(value).substring(1);	
		this.attribute = null;
		this.hasValue = false;
		ArrayList<CPabePolicy> stack = new ArrayList<CPabePolicy>();
		// GT >
		if(isGreater) {
			if(value >= 0) {
				// ((first bit zero) && (greater than complement remainder))
				// an and gate (i.e. 2 children and k=2)
				this.k = 2;
				// this is: (first bit zero)
				stack.add(new CPabePolicy(this.attStringBinMaskValue(att, 0, '0')));
				stack.add(this.constructRemainderPolicy(att, complement, true));
			}
			else {
				// (first bit zero) || ((first bit one) && (lesser than complement remainder))
				this.k = 1;
				// this is: (first bit zero)
				stack.add(new CPabePolicy(this.attStringBinMaskValue(att, 0, '0')));
				// an and gate
				CPabePolicy and = new CPabePolicy(2);
				and.children[0] = new CPabePolicy(this.attStringBinMaskValue(att, 0, '1'));
				and.children[1] = this.constructRemainderPolicy(att, complement, false);
				stack.add(and);
			}
		}
		// LT <
		else {
			if(value < 0) {
				// ((first bit one) && (greater than complement remainder))
				this.k = 2;
				// this is: (first bit one)
				stack.add(new CPabePolicy(this.attStringBinMaskValue(att, att.length() + 1, '1')));
				stack.add(this.constructRemainderPolicy(att, complement, true));
			}
			else {
				// (first bit one) || ((first bit zero) && (lesser than complement remainder))
				this.k = 1;
				stack.add(new CPabePolicy(this.attStringBinMaskValue(att, att.length() + 1, '1')));
				CPabePolicy and = new CPabePolicy(2);
				and.children[0] = new CPabePolicy(this.attStringBinMaskValue(att, 0, '0'));
				and.children[1] = this.constructRemainderPolicy(att, complement, false);
				stack.add(and);				
			}			
		}
		this.children = stack.toArray(new CPabePolicy[stack.size()]);
	}

	private CPabePolicy constructRemainderPolicy(String att, String complementValue, boolean isGreater) {
		System.out.println(complementValue);
		String attValue = null;
		CPabePolicy root = null;
		int len = complementValue.length();
		// copy first bit
		int firstBit = Integer.parseInt(complementValue.substring(0, 1));
		// and  then remove it
		complementValue = complementValue.substring(1);
		if(len == 1) {
			if(isGreater) {
				attValue = this.attStringBinMaskValue(att, 32 - len, '1');
				root = new CPabePolicy(attValue, true);
			}
			else {
				attValue = this.attStringBinMaskValue(att, 32 - len, '0');
				root = new CPabePolicy(attValue, true);
			}
		}
		else {
			if(isGreater) {
				if(firstBit == 1) {
					// AND
					root = new CPabePolicy(2);
					attValue = this.attStringBinMaskValue(att, 32 - len, '1');
					root.children[0] = new CPabePolicy(attValue, true);
					root.children[1] = this.constructRemainderPolicy(att, complementValue, isGreater);
				}
				else if(firstBit == 0) {
					// OR
					root  = new CPabePolicy(1, 2);
					attValue = this.attStringBinMaskValue(att, 32 - len, '1');
					root.children[0] = new CPabePolicy(attValue, true);
					root.children[1] = this.constructRemainderPolicy(att, complementValue, isGreater);
				}
			}
			else {
				if(firstBit == 1) {
					// OR
					root  = new CPabePolicy(1, 2);
					attValue = this.attStringBinMaskValue(att, 32 - len, '0');
					root.children[0] = new CPabePolicy(attValue, true);
					root.children[1] = this.constructRemainderPolicy(att, complementValue, isGreater);
				}
				else if(firstBit == 0) {
					// AND
					root = new CPabePolicy(2);
					attValue = this.attStringBinMaskValue(att, 32 - len, '0');
					root.children[0] = new CPabePolicy(attValue, true);
					root.children[1] = this.constructRemainderPolicy(att, complementValue, isGreater);				
				}
			}
		}
		return root;
	}

	// create a attribute string with value as a string bit mask 
	// covering everything but one single bit with *
	// i.e.: A:*******************************1
	public String attStringBinMaskValue(String att, int position, char value) {
		StringBuilder attributeValue = new StringBuilder(att + CPabeSettings.CPabeConstants.AVSPLIT + String.join("", Collections.nCopies(32, "*")));
		attributeValue.setCharAt(att.length() + CPabeSettings.CPabeConstants.AVSPLIT.length() + position, value);
		return attributeValue.toString();
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