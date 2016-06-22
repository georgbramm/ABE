package name.raess.abe.cp.objects;

import org.json.simple.JSONObject;

import it.unisa.dia.gas.jpbc.Element;
import name.raess.abe.cp.CPabeImportExport;

public class CPabeUserAttribute {
	public String attribute;		// String
	public Element dj;				// G2
	public Element djp;				// G1
	public CPabeUserAttribute(String sval) {
		this.attribute = sval;
	}
	public CPabeUserAttribute() {
	}
	public CPabeUserAttribute(String sval, Element dj, Element djp) {
		this.attribute = sval;
		this.dj = dj;
		this.djp = djp;
	}
	@SuppressWarnings("unchecked")
	public String toString() {
		JSONObject obj = new JSONObject();
		obj.put("description", this.attribute);
		obj.put("d", this.dj.toString());
		obj.put("dPrime", this.djp.toString());
		return obj.toJSONString();
	}
	@SuppressWarnings("unchecked")
	public String export() {
		JSONObject obj = new JSONObject();
		obj.put("desc", this.attribute);
		obj.put("dj", CPabeImportExport.b64encode(this.dj.toBytes()));
		obj.put("djPrime", CPabeImportExport.b64encode(this.djp.toBytes()));
		return obj.toJSONString();
	}
}
