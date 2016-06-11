package name.raess.abe.cp.objects;

import org.json.simple.JSONObject;

import it.unisa.dia.gas.jpbc.Element;
import name.raess.abe.cp.CPabeSettings;

public class CPabeUserAttribute {
	
	public String description;		// String
	public Element dj;				// G2
	public Element djp;				// G1
	
	public CPabeUserAttribute(String sval) {
		this.description = sval;
	}
	
	public CPabeUserAttribute() {
	}
	
	public CPabeUserAttribute(String sval, Element dj, Element djp) {
		this.description = sval;
		this.dj = dj;
		this.djp = djp;
	}	

	@SuppressWarnings("unchecked")
	public String toString() {
		JSONObject obj = new JSONObject();
		obj.put("description", this.description);
		obj.put("d", this.dj.toString());
		obj.put("dPrime", this.djp.toString());
		return obj.toJSONString();
	}
	
	@SuppressWarnings("unchecked")
	public String export() {
		JSONObject obj = new JSONObject();
		obj.put("desc", this.description);
		String encodedDj = org.apache.commons.codec.binary.Base64.encodeBase64String(this.dj.toBytes());
		String encodedDjPrime = org.apache.commons.codec.binary.Base64.encodeBase64String(this.djp.toBytes());
		obj.put("dj", encodedDj);
		obj.put("djPrime", encodedDjPrime);
		return obj.toJSONString();
	}
}
