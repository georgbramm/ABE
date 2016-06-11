package name.raess.abe.cp.objects;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import name.raess.abe.cp.CPabeSettings;

/* This Class represents a Master Secret Key (MSK)
 */
public class CPabeMasterSecret {
	public Element beta; 		// Zr
	public Element gAlpha; 		// G2

	// this creates a saved {msk} from a binary file located at loadfrom using 
	// the pairing in {pk}
	@SuppressWarnings({ "resource", "unchecked" })
	public CPabeMasterSecret(String loadfrom, CPabePublicParameters pk) throws IOException, ClassNotFoundException {
		FileInputStream fin = new FileInputStream(loadfrom);
		ObjectInputStream objin = new ObjectInputStream (fin);
		Object obj = objin.readObject();
		if (obj instanceof List<?>) {
			List<byte[]> list = (List<byte[]>) obj;
			this.beta = pk.p.getZr().newElement();
			this.beta.setFromBytes(list.get(0));
			this.gAlpha = pk.p.getG2().newElement();
			this.gAlpha.setFromBytes(list.get(1));
		}
	}

	// default ctor
	public CPabeMasterSecret() {
	}

	// saves this {msk} in binary format
	public void saveAs(String saveas) throws IOException {
		List<byte[]> list = new ArrayList<byte[]>();
		list.add(this.beta.toBytes());
		list.add(this.gAlpha.toBytes());
	    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(saveas));
	    out.writeObject(list);
	    out.close();
	}	
	
	// returns this {msk} as json String
	@SuppressWarnings({ "unchecked" })
	public String toString() {
		JSONObject obj = new JSONObject();
		JSONObject key = new JSONObject();
		key.put("beta", this.beta.toString());
		key.put("gHatAlpha", this.gAlpha.toString());
		obj.put("name", "msk");
		obj.put("key", key);
		return obj.toJSONString();
	}

	@SuppressWarnings("unchecked")
	public String exportBase64() {
		JSONObject obj = new JSONObject();
		obj.put("beta", CPabeObjectTools.b64encode(this.beta.toBytes()));
		obj.put("gAlpha", CPabeObjectTools.b64encode(this.gAlpha.toBytes()));
		String json = obj.toJSONString();
		String b64 = CPabeObjectTools.b64encode(json.getBytes()).replaceAll("(.{"+CPabeSettings.CPabeConstants.CHARSPERLINE+"})", "$1\n");
		b64 = CPabeSettings.CPabeConstants.MSKHEAD 
				+ CPabeSettings.versionString 
				+ b64 
				+ CPabeSettings.CPabeConstants.MSKTAIL;
		return b64;
	}

	public boolean importBase64(String b64, CPabePublicParameters pk) {
		// remove first two lines
		b64 = b64.substring(b64.indexOf(CPabeSettings.versionString) + CPabeSettings.versionString.length());
		// remove last line
		b64 = b64.substring(0, b64.lastIndexOf(CPabeSettings.CPabeConstants.MSKTAIL));
		// remove new lines
		b64 = b64.replace(CPabeSettings.CPabeConstants.NEWLINE, "");
		JSONParser parser = new JSONParser();
		try{
			Object obj = parser.parse(new String(CPabeObjectTools.b64decode(b64)));
			JSONObject jsonObj = (JSONObject)obj;
			this.beta = pk.p.getZr().newElement();
			this.beta.setFromBytes(CPabeObjectTools.b64decode((String) jsonObj.get("beta")));
			this.gAlpha = pk.p.getG2().newElement();
			this.gAlpha.setFromBytes(CPabeObjectTools.b64decode((String) jsonObj.get("gAlpha")));
			return true;
		}catch(ParseException pe){
			System.out.println("position: " + pe.getPosition());
			System.out.println(pe);
			return false;
		}
	}
}
