package name.raess.abe.cp.objects;

import java.io.FileOutputStream;
import java.io.IOException;
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
		obj.put("ct", this.cipherText.toString());
		return obj.toJSONString();
	}
	
	public void saveAs(String saveas) throws IOException {
		List<byte[]> list = new ArrayList<byte[]>();
		list.add(this.c.toBytes());
		list.add(this.cPrime.toBytes());
		list.add(this.cipherText.getBytes());
		// policy als json ?
		//list.addAll(this.policy.toByteList());
	    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(saveas));
	    out.writeObject(list);
	    out.close();
	}
	
	@SuppressWarnings("unchecked")
	public String exportBase64() {
		JSONObject obj = new JSONObject();
		obj.put("c", CPabeObjectTools.b64encode(this.c.toBytes()));
		obj.put("cPrime", CPabeObjectTools.b64encode(this.cPrime.toBytes()));
		obj.put("ct", CPabeObjectTools.b64encode(this.cipherText.getBytes()));
		obj.put("policy", this.policy.toJSON().toJSONString());
		return CPabeSettings.CPabeConstants.CTHEAD 
				+ CPabeSettings.versionString 
				+ CPabeObjectTools.b64encode(obj.toJSONString().getBytes()).replaceAll("(.{"+CPabeSettings.CPabeConstants.CHARSPERLINE+"})", "$1\n") 
				+ CPabeSettings.CPabeConstants.CTTAIL;
	}
	
	public boolean importBase64(String b64, CPabePublicParameters pk) {
		// remove first two lines
		b64 = b64.substring(b64.indexOf(CPabeSettings.versionString) + CPabeSettings.versionString.length());
		// remove last line
		b64 = b64.substring(0, b64.lastIndexOf(CPabeSettings.CPabeConstants.CTTAIL));
		// remove new lines
		b64 = b64.replace(CPabeSettings.CPabeConstants.NEWLINE, "");
		JSONParser parser = new JSONParser();
		try{
			Object obj = parser.parse(new String(CPabeObjectTools.b64decode(b64)));
			JSONObject jsonObj = (JSONObject)obj;
			this.c = pk.p.getG1().newElement();
			this.c.setFromBytes(CPabeObjectTools.b64decode((String) jsonObj.get("c")));
			this.cPrime = pk.p.getGT().newElement();
			this.cPrime.setFromBytes(CPabeObjectTools.b64decode((String) jsonObj.get("cPrime")));
			this.cipherText = new String(CPabeObjectTools.b64decode((String) jsonObj.get("ct")));
			Object objPolicy = parser.parse((String) jsonObj.get("policy"));
			this.policy = new CPabePolicy((JSONObject) objPolicy, pk);
			return true;
		}catch(ParseException pe){
			System.out.println("position: " + pe.getPosition());
			System.out.println(pe);
			return false;
		}
	}

}
