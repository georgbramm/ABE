package name.raess.abe.cp.objects;

import java.util.ArrayList;
import java.util.Base64;

import org.json.simple.JSONObject;

import it.unisa.dia.gas.jpbc.Element;
import name.raess.abe.cp.CPabeSettings;

public class CPabeUserKey {
	public Element d; 		// G2
	public ArrayList<CPabeUserAttribute> attributes;
	
	@SuppressWarnings("unchecked")
	public String toString() {
		JSONObject obj = new JSONObject();
		obj.put("d", this.d.toString());
		JSONObject attrs = new JSONObject();
		for(CPabeUserAttribute attr: attributes) {
			attrs.put("attribute", attr.toString());
		}
		obj.put("attributes", attrs);
		return obj.toJSONString();
	}
	
	public CPabeUserAttribute getAttribute(String a) {
		CPabeUserAttribute ret = null;
		for(CPabeUserAttribute attr: this.attributes) {
			if(attr.description.equals(a)) {
				ret = attr;
			}
		}
		return ret;
	}

	public void saveAs(String replace) {
		// TODO Auto-generated method stub
		
	}
}
