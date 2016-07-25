package name.raess.abe.cp.objects;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import it.unisa.dia.gas.jpbc.Element;
import name.raess.abe.cp.CPabeImportExport;
import name.raess.abe.cp.CPabeSettings;
import name.raess.abe.cp.CPabeTools;

/* This Class represents a Master Secret Key (MSK)
 */
public class CPabeMasterSecret {
	public Element beta; 		// Zr
	public Element gAlpha; 		// G2
	private String password;	// hashed password
	
	// default ctor
	public CPabeMasterSecret() {
	}
	
	// saves this {msk} in binary format
	public void saveAs(String saveas, String password) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException {
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(saveas));
	    out.writeObject(this.exportBase64(password));
	    out.close();
	}
	
	// loads this {msk} in binary format
	@SuppressWarnings({ "resource" })
	public void loadFrom(String loadfrom, String password, CPabePublicParameters pk) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		FileInputStream fin = new FileInputStream(loadfrom);
		ObjectInputStream objin = new ObjectInputStream (fin);
		Object obj = objin.readObject();
		if (obj instanceof String) {
			this.importBase64(obj.toString(), password, pk);
		}
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
	public String exportBase64(String password) throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException {
		this.password = CPabeTools.randomOracle(password);
		JSONObject obj = new JSONObject();
		obj.put("beta", CPabeImportExport.b64encode(this.beta.toBytes()));
		obj.put("gAlpha", CPabeImportExport.b64encode(this.gAlpha.toBytes()));
		String json = obj.toJSONString();
		String b64 = CPabeImportExport.b64encode(json.getBytes()).replaceAll("(.{"+CPabeSettings.CPabeConstants.CHARSPERLINE+"})", "$1\n");
		String[] enc = CPabeTools.aesEncrypt(this.password, b64.getBytes());
		b64 = enc[0] + CPabeSettings.CPabeConstants.SIGN + enc[1];
		b64 = CPabeSettings.CPabeConstants.HEAD.replaceAll(CPabeSettings.CPabeConstants.SIGN, CPabeSettings.CPabeConstants.MSK) 
				+ CPabeSettings.versionString 
				+ b64.replaceAll("(.{"+CPabeSettings.CPabeConstants.CHARSPERLINE+"})", "$1\n")
				+ CPabeSettings.CPabeConstants.TAIL.replaceAll(CPabeSettings.CPabeConstants.SIGN, CPabeSettings.CPabeConstants.MSK);
		return b64;
	}

	public boolean importBase64(String b64, String password, CPabePublicParameters pk) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		this.password = CPabeTools.randomOracle(password);
		// remove first two lines
		b64 = b64.substring(b64.indexOf(CPabeSettings.versionString) + CPabeSettings.versionString.length());
		// remove last line
		b64 = b64.substring(0, b64.lastIndexOf(CPabeSettings.CPabeConstants.TAIL.replaceAll(CPabeSettings.CPabeConstants.SIGN, CPabeSettings.CPabeConstants.MSK)));
		// remove new lines
		b64 = b64.replace(CPabeSettings.CPabeConstants.NEWLINE, "");
		String[] dec = new String[2];
		dec[0] = b64.substring(0, b64.indexOf(CPabeSettings.CPabeConstants.SIGN));
		dec[1] = b64.substring(b64.indexOf(CPabeSettings.CPabeConstants.SIGN) + CPabeSettings.CPabeConstants.SIGN.length());
		b64 = new String(CPabeTools.aesDecrypt(this.password, dec));
		JSONParser parser = new JSONParser();
		try{
			Object obj = parser.parse(new String(CPabeImportExport.b64decode(b64)));
			JSONObject jsonObj = (JSONObject)obj;
			this.beta = pk.p.getZr().newElement();
			this.beta.setFromBytes(CPabeImportExport.b64decode((String) jsonObj.get("beta")));
			this.gAlpha = pk.p.getG2().newElement();
			this.gAlpha.setFromBytes(CPabeImportExport.b64decode((String) jsonObj.get("gAlpha")));
			return true;
		}catch(ParseException e){
			System.out.println(e);
			return false;
		}
	}
}
