package name.raess.abe.cp;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import it.unisa.dia.gas.jpbc.Element;
import name.raess.abe.cp.CPabeSettings;
import name.raess.abe.cp.objects.CPabeCipherText;
import name.raess.abe.cp.objects.CPabeComp;
import name.raess.abe.cp.objects.CPabePolicy;
import name.raess.abe.cp.objects.CPabePolynomial;
import name.raess.abe.cp.objects.CPabePublicParameters;
import name.raess.abe.cp.objects.CPabeUserAttribute;
import name.raess.abe.cp.objects.CPabeUserKey;

public class CPabeTools {


	public static String symEncrypt(Element keyElement, byte[] data) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException {
		// Derive the key
        SecretKeySpec secret = CPabeTools.deriveKey(keyElement);
        //encrypt the message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        return CPabeObjectTools.b64encode(cipher.doFinal(data)) 
        		+ CPabeSettings.CPabeConstants.SPLIT 
        		+ CPabeObjectTools.b64encode(iv);
    }
	
	public static SecretKeySpec deriveKey(Element keyElement) throws NoSuchAlgorithmException {
        // convert element to bytes
        byte[] key = keyElement.toBytes();
        // try to get sha 256
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        // and use element byte value
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16); // use only 128 bit because of java restrictions =(
        SecretKeySpec secret = new SecretKeySpec(key, "AES");
        return secret;
	}

    public static byte[] symDecrypt(Element keyElement, CPabeCipherText ct) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    	String[] encrypted = ct.cipherText.split(CPabeSettings.CPabeConstants.SPLIT);
    	byte[] cipherText = CPabeObjectTools.b64decode(encrypted[0]);
    	byte[] iv = CPabeObjectTools.b64decode(encrypted[1]);
        // Derive the key
        SecretKeySpec secret = CPabeTools.deriveKey(keyElement); 
        // Decrypt the message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
        byte[] decryptedTextBytes = null;
        try {
            decryptedTextBytes = cipher.doFinal(cipherText);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return decryptedTextBytes;
    }

	public static void randomOracle(Element h, String attribute) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			byte[] digest = md.digest(attribute.getBytes());
			h.setFromHash(digest, 0, digest.length);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
    
	public static CPabePolicy parsePolicy(JSONObject policy) throws IOException {
		String att = null;
		int attValue = 0;
		JSONArray nodeArray;
		JSONObject nodeObject;
		CPabePolicy root = null;
		ArrayList<CPabePolicy> stack = new ArrayList<CPabePolicy>();
		for (Object key : policy.keySet()) {
	        //make uppercase and remove all numbers
			//than switch type
	        switch(key.toString().toUpperCase().replaceAll("[^A-Z]","")) {
	        case CPabeSettings.CPabeConstants.OR:
	        	root = new CPabePolicy(1);
	        	nodeArray = (JSONArray) policy.get(key);
	        	for (Object currentNode : nodeArray) {
	        		CPabePolicy node = CPabeTools.parsePolicy((JSONObject) currentNode);
	        		stack.add(node);
	        	}
	        	root.children = stack.toArray(new CPabePolicy[stack.size()]);
	        	break;
	        case CPabeSettings.CPabeConstants.AND:
	        	nodeArray = (JSONArray) policy.get(key);
	        	root = new CPabePolicy(nodeArray.size());
	        	for (Object currentNode : nodeArray) {
	        		CPabePolicy node = CPabeTools.parsePolicy((JSONObject) currentNode);
	        		stack.add(node);
	        	}
	        	root.children = stack.toArray(new CPabePolicy[stack.size()]);
	        	break;
	        case CPabeSettings.CPabeConstants.OF:
	        	nodeArray = (JSONArray) policy.get(key);
	        	int K = Integer.parseInt(key.toString().toUpperCase().replaceAll("[A-Z]",""));
	        	if(K>nodeArray.size()){
	        		System.err.println("Err: policy not decryptable");
	        		return null;
	        	}
	        	root = new CPabePolicy(K);
	        	for (Object currentNode : nodeArray) {
	        		CPabePolicy node = CPabeTools.parsePolicy((JSONObject) currentNode);
	        		stack.add(node);
	        	}
	        	root.children = stack.toArray(new CPabePolicy[stack.size()]);
	        	break;
	        case CPabeSettings.CPabeConstants.ATT:
	        	att = (String) policy.get(key);
	        	root = new CPabePolicy(att);
	        	break;
	        case CPabeSettings.CPabeConstants.VAL:
	        	attValue = Integer.parseInt((String) policy.get(key));
	        	root = new CPabePolicy(att, attValue); // 32 bit value needs 32 children =(
	        	break;  
	        case CPabeSettings.CPabeConstants.EQ:
	        	nodeObject = (JSONObject) policy.get(key);
	        	root = CPabeTools.parsePolicy(nodeObject);
	        	break;
	        case CPabeSettings.CPabeConstants.LT:
	        	nodeObject = (JSONObject) policy.get(key);
	        	root = CPabeTools.parseMathPolicy(nodeObject, CPabeSettings.CPabeConstants.LT, 0);
	        	break;
	        case CPabeSettings.CPabeConstants.LTEQ:
	        	nodeObject = (JSONObject) policy.get(key);
	        	root = CPabeTools.parseMathPolicy(nodeObject, CPabeSettings.CPabeConstants.LT, 1);
	        	break;	        	
	        case CPabeSettings.CPabeConstants.GT:
	        	nodeObject = (JSONObject) policy.get(key);
	        	root = CPabeTools.parseMathPolicy(nodeObject, CPabeSettings.CPabeConstants.GT, 0);
	        	break;
	        case CPabeSettings.CPabeConstants.GTEQ:
	        	nodeObject = (JSONObject) policy.get(key);
	        	root = CPabeTools.parseMathPolicy(nodeObject, CPabeSettings.CPabeConstants.GT, -1);
	        	break;	        	
	        default:
	        	System.out.println("error in JSON: unknown key" + key.toString());
	        	root = null;
	        	break;
	        }
	    }
		return root;
	}

	private static CPabePolicy parseMathPolicy(JSONObject policy, String operation, int shift) {
		String att = null;
		int attValue = 0;
		CPabePolicy root = null;		
		for (Object key : policy.keySet()) {
	        //make uppercase and remove all numbers
			//than switch type
	        switch(key.toString().toUpperCase().replaceAll("[^A-Z]","")) {
	        case CPabeSettings.CPabeConstants.ATT:
	        	att = (String) policy.get(key);
	        	break;
	        case CPabeSettings.CPabeConstants.VAL:
	        	attValue = Integer.parseInt((String) policy.get(key));
	        	// GTEQ = GT + 1 (shift by one)
	        	// 32 bit value needs 32 children =(
	        	if(operation == CPabeSettings.CPabeConstants.GTEQ) {
	        		root = new CPabePolicy(att, attValue + shift, true); 
	        	}
	        	// GT
	        	else if(operation == CPabeSettings.CPabeConstants.GT) {
	        		root = new CPabePolicy(att, attValue, true);
	        	}
	        	// LTEQ = LT - 1 (shift by minus one)
	        	else if(operation == CPabeSettings.CPabeConstants.LTEQ) {
	        		root = new CPabePolicy(att, attValue + shift, false);
	        	}
	        	// LT
	        	else if(operation == CPabeSettings.CPabeConstants.LT) {
	        		root = new CPabePolicy(att, attValue, false);
	        	}
	        	break; 
	        }
		}
		return root;
	}

	public static void bethencourtGoyal(CPabePolicy p, CPabePublicParameters pub, Element secret) throws NoSuchAlgorithmException {
		int i;
		Element t, h;
		t = pub.p.getZr().newElement();
		h = pub.p.getG2().newElement();
		// generate new random polynomial with fixed zero value (secret) and degree k-1
		p.q = new CPabePolynomial(p.k - 1, secret);
		if (p.children == null || p.children.length == 0) {
			// if this is an attribute
			p.cy = pub.p.getG1().newElement();
			p.cyPrime = pub.p.getG2().newElement();
			// set h to random oracle of attribute
			CPabeTools.randomOracle(h, p.attribute);
			p.cy = pub.g.duplicate();;
			p.cy.powZn(p.q.coef[0]); 	
			p.cyPrime = h.duplicate();
			p.cyPrime.powZn(p.q.coef[0]);
		} else {
			// if this is a threshold gate
			for (i = 0; i < p.children.length; i++) {
				t = p.q.evalPoly(pub.p.getZr().newElement().set(i + 1));
				CPabeTools.bethencourtGoyal(p.children[i], pub, t);
			}
		}
	}

	public static boolean checkSatisfy(CPabePolicy p, CPabeUserKey prv) {
		int i, l;
		String prvAttr;
		p.satisfiable = false;
		if (p.children == null || p.children.length == 0) {
			for (i = 0; i < prv.attributes.size(); i++) {
				prvAttr = prv.attributes.get(i).description;
				if (p != null && prvAttr.compareTo(p.attribute) == 0) {
					p.satisfiable = true;
					p.index = i;
					break;
				}
			}
		} else {
			for (i = 0; i < p.children.length; i++) {
				CPabeTools.checkSatisfy(p.children[i], prv);
			}
			l = 0;
			for (i = 0; i < p.children.length; i++) {
				if (p.children[i].satisfiable) {
					l++;
				}
			}
			if (l >= p.k) {
				p.satisfiable = true;
			}
		}
		return p.satisfiable;
	}

	public static Element decPolicyTree(CPabePolicy p, CPabeUserKey prv, CPabePublicParameters pub, Element exp) {
		if (p.children == null || p.children.length == 0) {
			return CPabeTools.decLeafFlatten(p, prv, pub, exp);
		}
		else {
			return CPabeTools.decInternalFlatten(p, prv, pub, exp);
		}
	}

	private static Element decInternalFlatten(CPabePolicy policy, CPabeUserKey prv, CPabePublicParameters pk, Element exp) {
		Element t, expnew;
		t = pk.p.getZr().newElement();
		expnew = pk.p.getZr().newElement();
		Element ret = pk.p.getGT().newElement();
		for (int i = 0; i < policy.satisfiableList.size(); i++) {
			t = CPabeTools.lagrangeCoef(pk, policy.satisfiableList, (policy.satisfiableList.get(i)).intValue());
			expnew = exp.duplicate();
			expnew.mul(t);
			ret.add(CPabeTools.decPolicyTree(policy.children[policy.satisfiableList.get(i) - 1], prv, pk, expnew));
		}
		return ret;
	}


	private static Element decLeafFlatten(CPabePolicy p, CPabeUserKey prv, CPabePublicParameters pub, Element exp) {
		CPabeUserAttribute c = prv.attributes.get(p.index);
		Element s = pub.p.getGT().newElement();
		Element t = pub.p.getGT().newElement();
		s = pub.p.pairing(p.cy, c.dj);
		t = pub.p.pairing(p.cyPrime, c.djp);
		t.invert();
		s.mul(t);
		s.powZn(exp);
		return pub.p.getGT().newElement().setToOne().mul(s);
	}

	private static Element lagrangeCoef(CPabePublicParameters pk, ArrayList<Integer> s, int i) {
		int j, k;
		Element t;
		Element r = pk.p.getZr().newElement();
		t = r.duplicate();
		r.setToOne();
		for (k = 0; k < s.size(); k++) {
			j = s.get(k).intValue();
			if (j != i) {
				t.set(-j);
				r.mul(t);
				t.set(i - j);
				t.invert();
				r.mul(t);
			}
		}
		return r;
	}

	public static void calculateMinLeaves(CPabePolicy p, CPabeUserKey prv) {
		int k, l;
		ArrayList<Integer> c = new ArrayList<Integer>();

		// if this is an attribute
		if (p.children == null || p.children.length == 0) {
			p.minLeaves = 1;
		}
		else {
			// if this is a threshold gate
			for (int i = 0; i < p.children.length; i++) {
				if (p.children[i].satisfiable) {
					CPabeTools.calculateMinLeaves(p.children[i], prv);
				}
				c.add(new Integer(i));
			}
			Collections.sort(c, new CPabeComp(p));
			p.satisfiableList = new ArrayList<Integer>();
			p.minLeaves = 0;
			l = 0;
			for (int i = 0; i < p.children.length && l < p.k; i++) {
				int cI = c.get(i).intValue(); /* c[i] */
				if (p.children[cI].satisfiable) {
					l++;
					p.minLeaves += p.children[cI].minLeaves;
					k = cI + 1;
					p.satisfiableList.add(new Integer(k));
				}
			}
		}
	}

	public static String[] convertValueAttributes(String[] attris) {
		ArrayList<String> ret = new ArrayList<String>();
		for(String attr: attris) {
			// if this attribute has a value convert it to 32 new attributes
			if(attr.contains("=")) {
				String[] attParts = attr.split("=");
				String attribute = attParts[0];
				int value = Integer.parseInt(attParts[1]);
				String mask = CPabeTools.convertToTwoComplement(value);
				for(int i = 0; i < 32; i++) {
					ret.add(attribute + CPabeSettings.CPabeConstants.AVSPLIT + CPabeTools.replaceSignedBitString(mask, i));
				}
			}
			// else keep it the same
			else {
				ret.add(attr);
			}
		}
		// and return new array of elements
		return ret.toArray(new String[ret.size()]);
	}
	
	private static String replaceSignedBitString(String value, int i) {
		String bitMask = String.join("", Collections.nCopies(32, "*"));
		StringBuilder attributeValue = new StringBuilder(bitMask);
		attributeValue.setCharAt(i, value.charAt(i));
		return attributeValue.toString();
	}

	// Converts an 32bit integer to an n-bit binary signed String
	// (i.e. in two complements format).
	public static String convertToTwoComplement(int myNum){
		if(myNum > 0) {
			return String.format("%32s", Integer.toBinaryString(myNum)).replace(' ', '0');
		}
		else {
			return String.format("%32s", Integer.toBinaryString(myNum)).replace(' ', '1');
		}
	}
}
