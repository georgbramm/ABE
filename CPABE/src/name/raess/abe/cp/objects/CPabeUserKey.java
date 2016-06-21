package name.raess.abe.cp.objects;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import it.unisa.dia.gas.jpbc.Element;
import name.raess.abe.cp.CPabeObjectTools;
import name.raess.abe.cp.CPabeSettings;

/* This Class represents a User Key (SK)
 */
public class CPabeUserKey {
	public Element d; 										// G2
	public ArrayList<CPabeUserAttribute> attributes;		// list of attributes
	
	// this creates a saved {sk} from a binary file located at loadfrom using 
	// the pairing in {pk}
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
	
	// default ctor
	public CPabeUserKey() {
	}

	@SuppressWarnings("unchecked")
	public String toString() {
		JSONObject obj = new JSONObject();
		obj.put("d", this.d.toString());
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
		String encodedD = CPabeObjectTools.b64encode(this.d.toBytes());
		obj.put("d", encodedD);
		JSONArray attrs = new JSONArray();
		for(CPabeUserAttribute attr: attributes) {
			attrs.add(attr.export());
		}
		obj.put("attrs", attrs);
		String json = obj.toJSONString();
		String b64 = CPabeObjectTools.b64encode(json.getBytes()).replaceAll("(.{"+CPabeSettings.CPabeConstants.CHARSPERLINE+"})", "$1\n");
		b64 = CPabeSettings.CPabeConstants.SKHEAD 
				+ CPabeSettings.versionString 
				+ b64 
				+ CPabeSettings.CPabeConstants.SKTAIL;
		return b64;
	}

	public boolean importBase64(String b64, CPabePublicParameters pk) {
		// remove first two lines
		b64 = b64.substring(b64.indexOf(CPabeSettings.versionString) + CPabeSettings.versionString.length());
		// remove last line
		b64 = b64.substring(0, b64.lastIndexOf(CPabeSettings.CPabeConstants.SKTAIL));
		b64 = b64.replace(CPabeSettings.CPabeConstants.NEWLINE, "");
		byte[] data = CPabeObjectTools.b64decode(b64);
		JSONParser parser = new JSONParser();
		try{
	         Object obj = parser.parse(new String(data));
	         JSONObject jsonObj = (JSONObject)obj;
	         byte[] encodedD = CPabeObjectTools.b64decode((String) jsonObj.get("d")); 
	         this.d = pk.p.getG2().newElement();
	         this.d.setFromBytes(encodedD);
	         JSONArray attrs = (JSONArray)jsonObj.get("attrs");
	         this.attributes = new ArrayList<CPabeUserAttribute>();
	         for (int i = 0; i < attrs.size(); i++) {
	        	 Object attrParser = parser.parse((String) attrs.get(i));
	        	 JSONObject jsonAttrObj = (JSONObject)attrParser;
	        	 String desc = (String) jsonAttrObj.get("desc");
	        	 byte[] encodedDj = CPabeObjectTools.b64decode((String) jsonAttrObj.get("dj"));
	        	 byte[] encodedDjPrime = CPabeObjectTools.b64decode((String) jsonAttrObj.get("djPrime"));
	        	 CPabeUserAttribute newAttribute = new CPabeUserAttribute(desc);
	        	 newAttribute.dj = pk.p.getG2().newElement();
	        	 newAttribute.dj.setFromBytes(encodedDj);
	        	 newAttribute.djp = pk.p.getG1().newElement();
	        	 newAttribute.djp.setFromBytes(encodedDjPrime);
	        	 this.attributes.add(newAttribute);
	         }
	         return true;

	      }catch(ParseException pe){
	         System.out.println("position: " + pe.getPosition());
	         System.out.println(pe);
	         return false;
	      }
	}
}
