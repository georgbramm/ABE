package name.raess.abe.cp.objects;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

import org.json.simple.JSONObject;

import it.unisa.dia.gas.jpbc.Element;

/* This Class represents a Master Secret Key (MSK)
 * and consists of the two Elements beta (from Zr) and
 * g^alpha (from G2).
 */
public class CPabeMasterSecret {
	public Element beta; 		// Zr
	public Element gAlpha; 	// G2

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

	public CPabeMasterSecret() {
	}

	public void saveAs(String saveas) throws IOException {
		List<byte[]> list = new ArrayList<byte[]>();
		list.add(this.beta.toBytes());
		list.add(this.gAlpha.toBytes());
	    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(saveas));
	    out.writeObject(list);
	    out.close();
	}	
	
	public String toString() {
		JSONObject obj = new JSONObject();
		JSONObject key = new JSONObject();
		key.put("beta", this.beta.toString());
		key.put("gHatAlpha", this.gAlpha.toString());
		obj.put("name", "msk");
		obj.put("key", key);
		return obj.toJSONString();
	}
}
