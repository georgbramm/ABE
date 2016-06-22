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
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import name.raess.abe.cp.CPabeImportExport;
import name.raess.abe.cp.CPabeSettings;

/* This Class represents a Public Parameters Key (PK)
 */
public class CPabePublicParameters {
	// pairing & parameters
	public Pairing p;
	public PairingParameters pairingParams;
	// elements
	public Element g;			// G1
	public Element gp;			// G2
	public Element h;			// G1
	public Element f;			// G1
	public Element gHatAlpha;	// GT

	// this creates a saved {pk} from a binary file located at loadfrom
	@SuppressWarnings({ "unchecked", "resource" })
	public CPabePublicParameters(String loadfrom) throws IOException, ClassNotFoundException {
		FileInputStream fin = new FileInputStream(loadfrom);
		ObjectInputStream objin = new ObjectInputStream(fin);
		Object obj = objin.readObject();
    	if (obj instanceof PairingParameters) {
			PairingParameters params = (PairingParameters) obj;
			this.pairingParams = params;
			this.p = PairingFactory.getPairing(this.pairingParams);
		}
    	obj = objin.readObject();
		if (obj instanceof List<?>) {
			List<byte[]> list = (List<byte[]>) obj;
			this.g = this.p.getG1().newElement();
			this.g.setFromBytes(list.get(0));
			this.gp = this.p.getG2().newElement();
			this.gp.setFromBytes(list.get(1));
			this.h = this.p.getG1().newElement();
			this.h.setFromBytes(list.get(2));
			this.f = this.p.getG1().newElement();
			this.f.setFromBytes(list.get(3));
			this.gHatAlpha = this.p.getGT().newElement();
			this.gHatAlpha.setFromBytes(list.get(4));
		}		
	}

	// default ctor
	public CPabePublicParameters() {
	}

	// this saves this {pk} as a binary file located at saveas
	public void saveAs(String saveas) throws IOException {
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(saveas));
		List<byte[]> list = new ArrayList<byte[]>();
		list.add(this.g.toBytes()); 		// 0
		list.add(this.gp.toBytes());		// 1
		list.add(this.h.toBytes());			// 2
		list.add(this.f.toBytes());			// 3
		list.add(this.gHatAlpha.toBytes());	// 4
		out.writeObject(this.pairingParams);
		out.writeObject(list);
	    out.close();		    
	}
	
	// export this {pk} as json string
	@SuppressWarnings("unchecked")
	public String toString() {
		JSONObject obj = new JSONObject();
		JSONObject key = new JSONObject();
		key.put("g", this.g.toString());
		key.put("gp", this.gp.toString());
		key.put("gHatAlpha", this.gHatAlpha.toString());
		key.put("h", this.h.toString());
		key.put("f", this.f.toString());
		key.put("pairing", this.pairingParams.toString());
		//key.put("pairing", this.pairingParams.toString() );
		obj.put("name", "pk");
		obj.put("key", key);		
		return key.toJSONString();
	}

	// export this {pk} in classical base64 encoding
	@SuppressWarnings("unchecked")
	public String exportBase64() throws IOException {
		JSONObject obj = new JSONObject();
		obj.put("g", CPabeImportExport.b64encode(this.g.toBytes()));
		obj.put("gp", CPabeImportExport.b64encode(this.gp.toBytes()));
		obj.put("h", CPabeImportExport.b64encode(this.h.toBytes()));
		obj.put("f", CPabeImportExport.b64encode(this.f.toBytes()));
		obj.put("gHatAlpha", CPabeImportExport.b64encode(this.gHatAlpha.toBytes()));
		obj.put("pairing", CPabeImportExport.b64encode(CPabeImportExport.convertToBytes(this.pairingParams)));
		String json = obj.toJSONString();
		String b64 = CPabeImportExport.b64encode(json.getBytes()).replaceAll("(.{"+CPabeSettings.CPabeConstants.CHARSPERLINE+"})", "$1\n");
		b64 = CPabeSettings.CPabeConstants.HEAD.replaceAll(CPabeSettings.CPabeConstants.SIGN, CPabeSettings.CPabeConstants.PK) 
				+ CPabeSettings.versionString 
				+ b64 
				+ CPabeSettings.CPabeConstants.TAIL.replaceAll(CPabeSettings.CPabeConstants.SIGN, CPabeSettings.CPabeConstants.PK);
		return b64;
	}	

	public boolean importBase64(String b64) throws ClassNotFoundException, IOException {
		// remove first two lines
		b64 = b64.substring(b64.indexOf(CPabeSettings.versionString) + CPabeSettings.versionString.length());
		// remove last line
		b64 = b64.substring(0, b64.lastIndexOf(CPabeSettings.CPabeConstants.TAIL.replaceAll(CPabeSettings.CPabeConstants.SIGN, CPabeSettings.CPabeConstants.PK)));
		// remove new lines
		b64 = b64.replace(CPabeSettings.CPabeConstants.NEWLINE, "");
		JSONParser parser = new JSONParser();
		try{
			Object obj = parser.parse(new String(CPabeImportExport.b64decode(b64)));
	        JSONObject jsonObj = (JSONObject)obj;
	        PairingParameters params = (PairingParameters) CPabeImportExport.convertFromBytes(CPabeImportExport.b64decode((String) jsonObj.get("pairing")));
			this.pairingParams = params;
			this.p = PairingFactory.getPairing(this.pairingParams);
			this.g = this.p.getG1().newElement();
			this.g.setFromBytes(CPabeImportExport.b64decode((String) jsonObj.get("g")));
			this.gp = this.p.getG2().newElement();
			this.gp.setFromBytes(CPabeImportExport.b64decode((String) jsonObj.get("gp")));
			this.h = this.p.getG1().newElement();
			this.h.setFromBytes(CPabeImportExport.b64decode((String) jsonObj.get("h")));
			this.f = this.p.getG1().newElement();
			this.f.setFromBytes(CPabeImportExport.b64decode((String) jsonObj.get("f")));
			this.gHatAlpha = this.p.getGT().newElement();
			this.gHatAlpha.setFromBytes(CPabeImportExport.b64decode((String) jsonObj.get("gHatAlpha")));
	        return true;
	      }catch(ParseException pe){
	         System.out.println("position: " + pe.getPosition());
	         System.out.println(pe);
	         return false;
	      }
	}
}
