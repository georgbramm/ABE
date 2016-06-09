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
import java.util.Base64;
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
import it.unisa.dia.gas.jpbc.Pairing;
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
		System.out.println("encryption key:" + keyElement.toString());
        // Derive the key
        SecretKeySpec secret = CPabeTools.deriveKey(keyElement);
        //encrypt the message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        return Base64.getEncoder().encodeToString(cipher.doFinal(data)) + CPabeSettings.SPLIT + Base64.getEncoder().encodeToString(iv);
    }
	
	public static SecretKeySpec deriveKey(Element keyElement) throws NoSuchAlgorithmException {
        // Derive the key
        byte[] key = keyElement.toBytes();
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16); // use only first 128 bit because of stupid java restrictions?
        SecretKeySpec secret = new SecretKeySpec(key, "AES");
        return secret;
	}

    public static String symDecrypt(Element keyElement, CPabeCipherText ct) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    	System.out.println("decryption key:" + keyElement.toString());
    	String[] encrypted = ct.cipherText.split(CPabeSettings.SPLIT);
    	byte[] cipherText = Base64.getDecoder().decode(encrypted[0]);
    	byte[] iv = Base64.getDecoder().decode(encrypted[1]);
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
        return new String(decryptedTextBytes);
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
		CPabePolicy root = null;
		ArrayList<CPabePolicy> stack = new ArrayList<CPabePolicy>();
		for (Object key : policy.keySet()) {
	        //make uppercase and remove all numbers
			//than switch type
	        switch(key.toString().toUpperCase().replaceAll("[^A-Z]","")) {
	        case CPabeSettings.OR:
	        	root = new CPabePolicy(1);
	        	nodeArray = (JSONArray) policy.get(key);
	        	for (Object currentNode : nodeArray) {
	        		CPabePolicy node = CPabeTools.parsePolicy((JSONObject) currentNode);
	        		stack.add(node);
	        	}
	        	root.children = stack.toArray(new CPabePolicy[stack.size()]);
	        	break;
	        case CPabeSettings.AND:
	        	nodeArray = (JSONArray) policy.get(key);
	        	root = new CPabePolicy(nodeArray.size());
	        	for (Object currentNode : nodeArray) {
	        		CPabePolicy node = CPabeTools.parsePolicy((JSONObject) currentNode);
	        		stack.add(node);
	        	}
	        	root.children = stack.toArray(new CPabePolicy[stack.size()]);
	        	break;
	        case CPabeSettings.OF:
	        	//make uppercase and remove all chars
	        	String K = key.toString().toUpperCase().replaceAll("[A-Z]","");
	        	root = new CPabePolicy(K);
	        	nodeArray = (JSONArray) policy.get(key);
	        	for (Object currentNode : nodeArray) {
	        		CPabePolicy node = CPabeTools.parsePolicy((JSONObject) currentNode);
	        		stack.add(node);
	        	}
	        	root.children = stack.toArray(new CPabePolicy[stack.size()]);
	        	break;
	        case CPabeSettings.ATT:
	        	att = (String) policy.get(key);
	        	root = new CPabePolicy(att);
	        	break;
	        case CPabeSettings.VAL:
	        	attValue = Integer.parseInt((String) policy.get(key));
	        	root = new CPabePolicy(att, attValue); // 32 bit value needs 32 children =(
	        	break;  
	        case CPabeSettings.EQ:
	        	attValue = Integer.parseInt((String) policy.get(key));
	        	root = new CPabePolicy(att, attValue); // 32 bit value needs 32 children =(	        	
	        	break;      	
	        default:
	        	System.out.println("error in JSON: unknown key" + key.toString());
	        	root = null;
	        	break;
	        }
	    }
		return root;
	}

	public static void fillPolicy(CPabePolicy p, CPabePublicParameters pub, Element e) throws NoSuchAlgorithmException {
		int i;
		Element r, t, h;
		Pairing pairing = pub.p;
		r = pairing.getZr().newElement();
		t = pairing.getZr().newElement();
		h = pairing.getG2().newElement();
		// generate new random polynomial with fixed 0 value (e)
		p.q = new CPabePolynomial(p.k - 1, e);
		if (p.children == null || p.children.length == 0) {
			p.cy = pairing.getG1().newElement();
			p.cy_Prime = pairing.getG2().newElement();
			// set h to random oracle of attribute
			CPabeTools.randomOracle(h, p.attribute);
			p.cy = pub.g.duplicate();;
			p.cy.powZn(p.q.coef[0]); 	
			p.cy_Prime = h.duplicate();
			p.cy_Prime.powZn(p.q.coef[0]);
		} else {
			for (i = 0; i < p.children.length; i++) {
				r.set(i + 1);
				CPabeTools.evalPoly(t, p.q, r);
				CPabeTools.fillPolicy(p.children[i], pub, t);
			}
		}

	}

	private static void evalPoly(Element r, CPabePolynomial q, Element x) {
		int i;
		Element s, t;
		s = r.duplicate();
		t = r.duplicate();
		r.setToZero();
		t.setToOne();
		for (i = 0; i < q.degree + 1; i++) {
			s = q.coef[i].duplicate();
			s.mul(t); 
			r.add(s);
			t.mul(x);
		}

	}

	public static void checkSatisfy(CPabePolicy p, CPabeUserKey prv) {
		int i, l;
		String prvAttr;
		p.satisfiable = false;
		if (p.children == null || p.children.length == 0) {
			for (i = 0; i < prv.attributes.size(); i++) {
				prvAttr = prv.attributes.get(i).description;
				if (prvAttr.compareTo(p.attribute) == 0) {
					p.satisfiable = true;
					p.index = i;
					break;
				}
			}
		} else {
			for (i = 0; i < p.children.length; i++)
				checkSatisfy(p.children[i], prv);

			l = 0;
			for (i = 0; i < p.children.length; i++)
				if (p.children[i].satisfiable)
					l++;

			if (l >= p.k)
				p.satisfiable = true;
		}
	}

	public static void decFlatten(Element r, CPabePolicy p, CPabeUserKey prv, CPabePublicParameters pub) {
		Element one;
		one = pub.p.getZr().newElement();
		one.setToOne();
		r.setToOne();
		CPabeTools.decNodeFlatten(r, one, p, prv, pub);
	}

	private static void decNodeFlatten(Element r, Element exp, CPabePolicy p, CPabeUserKey prv, CPabePublicParameters pub) {
		if (p.children == null || p.children.length == 0) {
			CPabeTools.decLeafFlatten(r, exp, p, prv, pub);
		}
		else {
			CPabeTools.decInternalFlatten(r, exp, p, prv, pub);
		}
	}

	private static void decInternalFlatten(Element r, Element exp,
			CPabePolicy p, CPabeUserKey prv, CPabePublicParameters pub) {
		int i;
		Element t, expnew;
		t = pub.p.getZr().newElement();
		expnew = pub.p.getZr().newElement();
		for (i = 0; i < p.satisfiableList.size(); i++) {
			CPabeTools.lagrangeCoef(t, p.satisfiableList, (p.satisfiableList.get(i)).intValue());
			expnew = exp.duplicate();
			expnew.mul(t);
			decNodeFlatten(r, expnew, p.children[p.satisfiableList.get(i) - 1], prv, pub);
		}
	}

	private static void lagrangeCoef(Element r, ArrayList<Integer> s, int i) {
		int j, k;
		Element t;
		t = r.duplicate();
		r.setToOne();
		for (k = 0; k < s.size(); k++) {
			j = s.get(k).intValue();
			if (j == i)
				continue;
			t.set(-j);
			r.mul(t);
			t.set(i - j);
			t.invert();
			r.mul(t);
		}
	}


	private static void decLeafFlatten(Element r, Element exp, CPabePolicy p,
			CPabeUserKey prv, CPabePublicParameters pub) {
		CPabeUserAttribute c;
		Element s, t;
		c = prv.attributes.get(p.index);
		s = pub.p.getGT().newElement();
		t = pub.p.getGT().newElement();
		s = pub.p.pairing(p.cy, c.dj);
		t = pub.p.pairing(p.cy_Prime, c.djp);
		t.invert();
		s.mul(t);
		s.powZn(exp);

		r.mul(s);
	}

	public static void pickSatisfyMinLeaves(CPabePolicy p, CPabeUserKey prv) {
		int i, k, l, c_i;
		int len;
		ArrayList<Integer> c = new ArrayList<Integer>();

		if (p.children == null || p.children.length == 0)
			p.minLeaves = 1;
		else {
			len = p.children.length;
			for (i = 0; i < len; i++)
				if (p.children[i].satisfiable)
					CPabeTools.pickSatisfyMinLeaves(p.children[i], prv);

			for (i = 0; i < len; i++)
				c.add(new Integer(i));

			Collections.sort(c, new CPabeComp(p));

			p.satisfiableList = new ArrayList<Integer>();
			p.minLeaves = 0;
			l = 0;

			for (i = 0; i < len && l < p.k; i++) {
				c_i = c.get(i).intValue(); /* c[i] */
				if (p.children[c_i].satisfiable) {
					l++;
					p.minLeaves += p.children[c_i].minLeaves;
					k = c_i + 1;
					p.satisfiableList.add(new Integer(k));
				}
			}
		}
	}

}
