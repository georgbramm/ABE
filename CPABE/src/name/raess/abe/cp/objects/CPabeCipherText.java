package name.raess.abe.cp.objects;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import it.unisa.dia.gas.jpbc.Element;
import name.raess.abe.cp.CPabeImportExport;
import name.raess.abe.cp.CPabeSettings;

public class CPabeCipherText {
	public CPabePolicy policy;	// the policy tree
	public Element c;			// from G1
	public Element cPrime;		// from GT
	public String cipherText;	// AES encrypted data
	public String iv;			// AES IV
	
	// default ctor
	public CPabeCipherText() {
	}
	
	// return as json string representation
	@SuppressWarnings("unchecked")
	public String toString() {
		JSONObject obj = new JSONObject();
		obj.put("c", this.c.toString());
		obj.put("cPrime", this.cPrime.toString());
		obj.put("ct", this.cipherText.toString());
		obj.put("iv", this.iv.toString());
		obj.put("policy", this.policy.toString());
		return obj.toJSONString();
	}
	
	// save in a binary file
	public void saveAs(String saveas) throws IOException {
		List<byte[]> list = new ArrayList<byte[]>();
		list.add(this.c.toBytes());
		list.add(this.cPrime.toBytes());
		list.add(this.cipherText.getBytes());
		list.add(this.iv.getBytes());
		list.add(this.policy.toJSON().toJSONString().getBytes());
	    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(saveas));
	    out.writeObject(list);
	    out.close();
	}

	// this sets and loads this {pk} from a binary file located at loadfrom
	@SuppressWarnings({ "unchecked", "resource" })
	public void loadFrom(String loadfrom, CPabePublicParameters pk) throws IOException, ClassNotFoundException, ParseException {
		FileInputStream fin = new FileInputStream(loadfrom);
		ObjectInputStream objin = new ObjectInputStream(fin);
		Object obj = objin.readObject();
		if (obj instanceof List<?>) {
			List<byte[]> list = (List<byte[]>) obj;
			this.c = pk.p.getG1().newElement();
			this.c.setFromBytes(list.get(0));
			this.cPrime = pk.p.getGT().newElement();
			this.cPrime.setFromBytes(list.get(1));
			this.cipherText = new String(list.get(2));
			this.iv = new String(list.get(3));
			JSONParser parser = new JSONParser();
			JSONObject jsonPolicy = (JSONObject) parser.parse(new String(list.get(4)));
			this.policy = new CPabePolicy(jsonPolicy, pk);
		}		
	}
	
	// return as base64 encoded json string
	@SuppressWarnings("unchecked")
	public String exportBase64() {
		JSONObject obj = new JSONObject();
		obj.put("c", CPabeImportExport.b64encode(this.c.toBytes()));
		obj.put("cPrime", CPabeImportExport.b64encode(this.cPrime.toBytes()));
		obj.put("ct", CPabeImportExport.b64encode(this.cipherText.getBytes()));
		obj.put("iv", CPabeImportExport.b64encode(this.iv.getBytes()));
		obj.put("policy", this.policy.toJSON().toJSONString());
		return CPabeSettings.CPabeConstants.HEAD.replaceAll(CPabeSettings.CPabeConstants.SIGN, CPabeSettings.CPabeConstants.CT) 
				+ CPabeSettings.versionString 
				+ CPabeImportExport.b64encode(obj.toJSONString().getBytes()).replaceAll("(.{"+CPabeSettings.CPabeConstants.CHARSPERLINE+"})", "$1\n") 
				+ CPabeSettings.CPabeConstants.TAIL.replaceAll(CPabeSettings.CPabeConstants.SIGN, CPabeSettings.CPabeConstants.CT);
	}
	
	// import from a base64 encoded json string
	// using CPabePublicParameters
	public boolean importBase64(String b64, CPabePublicParameters pk) {
		// remove first two lines
		b64 = b64.substring(b64.indexOf(CPabeSettings.versionString) + CPabeSettings.versionString.length());
		// remove last line
		b64 = b64.substring(0, b64.lastIndexOf(CPabeSettings.CPabeConstants.TAIL.replaceAll(CPabeSettings.CPabeConstants.SIGN, CPabeSettings.CPabeConstants.CT)));
		// remove new lines
		b64 = b64.replace(CPabeSettings.CPabeConstants.NEWLINE, "");
		JSONParser parser = new JSONParser();
		try{
			Object obj = parser.parse(new String(CPabeImportExport.b64decode(b64)));
			JSONObject jsonObj = (JSONObject)obj;
			this.c = pk.p.getG1().newElement();
			this.c.setFromBytes(CPabeImportExport.b64decode((String) jsonObj.get("c")));
			this.cPrime = pk.p.getGT().newElement();
			this.cPrime.setFromBytes(CPabeImportExport.b64decode((String) jsonObj.get("cPrime")));
			this.cipherText = new String(CPabeImportExport.b64decode((String) jsonObj.get("ct")));
			this.iv = new String(CPabeImportExport.b64decode((String) jsonObj.get("iv")));
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
