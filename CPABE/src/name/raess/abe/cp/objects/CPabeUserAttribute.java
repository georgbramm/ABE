package name.raess.abe.cp.objects;

import org.json.simple.JSONObject;

import it.unisa.dia.gas.jpbc.Element;
import name.raess.abe.cp.CPabeSettings;

public class CPabeUserAttribute {
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
	
	public String description;		// String
	public Element dj;				// G2
	public Element djp;				// G1
	
	@SuppressWarnings("unchecked")
	public String toString() {
		JSONObject obj = new JSONObject();
		obj.put("description", this.description);
		if(CPabeSettings.consoleDetails) {
			obj.put("d", this.dj.toString());
			obj.put("dPrime", this.djp.toString());
		}
		return obj.toJSONString();
	}
}
