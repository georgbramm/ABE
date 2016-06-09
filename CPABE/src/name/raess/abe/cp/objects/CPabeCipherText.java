package name.raess.abe.cp.objects;

import org.json.simple.JSONObject;

import it.unisa.dia.gas.jpbc.Element;

public class CPabeCipherText {
	public CPabePolicy policy;	// the policy tree
	public Element c;			// from G1
	public Element cPrime;		// from GT
	public String cipherText;	// AES encrypted data using Base64 coding
	
	@SuppressWarnings("unchecked")
	public String toString() {
		JSONObject obj = new JSONObject();
		obj.put("c", this.c.toString());
		obj.put("cPrime", this.cPrime.toString());
		obj.put("policy", this.policy.toString());
		return obj.toJSONString();
	}	
}
