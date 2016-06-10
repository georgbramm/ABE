package name.raess.abe.cp.objects;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import it.unisa.dia.gas.jpbc.Element;
import name.raess.abe.cp.CPabeSettings;

public class CPabeUserKey {
	public Element d; 		// G2
	public ArrayList<CPabeUserAttribute> attributes;
	
	@SuppressWarnings({ "resource", "unchecked" })
	public CPabeUserKey(String loadfrom, CPabePublicParameters pk) throws ClassNotFoundException, IOException {
		FileInputStream fin = new FileInputStream(loadfrom);
		ObjectInputStream objin = new ObjectInputStream (fin);
		Object obj = objin.readObject();
		this.attributes = new ArrayList<CPabeUserAttribute>();
		if (obj instanceof List<?>) {
			List<byte[]> list = (List<byte[]>) obj;
			this.d = pk.p.getG2().newElement();
			this.d.setFromBytes(list.get(0));
			for(int j = 1; j < list.size(); j += 3) {
				String desc = new String(list.get(j), "UTF-8");
				Element dj = pk.p.getG2().newElement();
				dj.setFromBytes(list.get(j + 1));
				Element djp = pk.p.getG1().newElement();
				djp.setFromBytes(list.get(j + 2));
				CPabeUserAttribute a = new CPabeUserAttribute(desc, dj , djp);
				this.attributes.add(a);
			}
		}
	}
	
	public CPabeUserKey() {
	}

	@SuppressWarnings("unchecked")
	public String toString() {
		JSONObject obj = new JSONObject();
		if(CPabeSettings.consoleDetails) {
			obj.put("d", this.d.toString());
		}
		JSONArray attrs = new JSONArray();
		for(CPabeUserAttribute attr: attributes) {
			attrs.add(attr.toString());
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

	public void saveAs(String saveas) throws IOException {
		List<byte[]> list = new ArrayList<byte[]>();
		list.add(this.d.toBytes());
		for(int x = 0;x < this.attributes.size(); x++) {
			list.add(this.attributes.get(x).description.getBytes());
			list.add(this.attributes.get(x).dj.toBytes());
			list.add(this.attributes.get(x).djp.toBytes());
		}
	    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(saveas));
	    out.writeObject(list);
	    out.close();
	}

	public String export() {
		return "";
	}
}
