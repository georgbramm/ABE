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
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

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

	@SuppressWarnings("unchecked")
	public String exportBase64() throws UnsupportedEncodingException {
		JSONObject obj = new JSONObject();
		String encodedD = org.apache.commons.codec.binary.Base64.encodeBase64String(this.d.toBytes());
		obj.put("d", encodedD);
		System.out.print("d_old:"+this.d.toString()+"\n");
		JSONArray attrs = new JSONArray();
		for(CPabeUserAttribute attr: attributes) {
			attrs.add(attr.export());
		}
		obj.put("attrs", attrs);
		String json = obj.toJSONString();
		String b64 = org.apache.commons.codec.binary.Base64.encodeBase64String(json.getBytes()).replaceAll("(.{"+CPabeSettings.CHARSPERLINE+"})", "$1\n");
		b64 = CPabeSettings.SKHEAD + CPabeSettings.versionString + b64 + CPabeSettings.SKTAIL;
		return b64;
	}

	public boolean importBase64(String b64, CPabePublicParameters pk) {
		// remove first two lines
		b64 = b64.substring(b64.indexOf(CPabeSettings.versionString) + CPabeSettings.versionString.length());
		// remove last line
		b64 = b64.substring(0, b64.lastIndexOf(CPabeSettings.SKTAIL));
		b64 = b64.replace(CPabeSettings.NEWLINE, "");
		byte[] data = org.apache.commons.codec.binary.Base64.decodeBase64(b64);
		JSONParser parser = new JSONParser();
		try{
	         Object obj = parser.parse(new String(data));
	         JSONObject jsonObj = (JSONObject)obj;
	         System.out.print("json:"+jsonObj.toString()+"\n");
	         byte[] encodedD = org.apache.commons.codec.binary.Base64.decodeBase64((String) jsonObj.get("d"));	         
	         this.d = pk.p.getG2().newElement();
	         this.d.setFromBytes(encodedD);
	         System.out.print("d_new:"+d.toString());
	         JSONArray attrs = (JSONArray)jsonObj.get("attrs");
	         for (int i = 0; i < attrs.size(); i++) {
	        	 String attr = (String) attrs.get(i);
	        	 System.out.print(attr);
	        	 //   String desc = (String) attr.get("desc");
	        	 //   String dj = (String) attr.get("d");
	        	 //   String djPrime = (String) attr.get("dPrime");
	        	    //this.attributes.add(new CPabeUserAttribute(desc, dj, djPrime));
	        	}
	         return true;

	      }catch(ParseException pe){
	         System.out.println("position: " + pe.getPosition());
	         System.out.println(pe);
	         return false;
	      }
	}
}
