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
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class CPabePublicParameters {
	// pairing & parameters
	public Pairing p;
	public PairingParameters pairingParams;
	// elements
	public Element g;			// G1
	public Element gp;			// G2
	public Element h;			// G1
	public Element f;			// G1
	public Element gAlpha;	// GT

	@SuppressWarnings({ "unchecked", "resource" })
	public CPabePublicParameters(String loadfrom) throws IOException, ClassNotFoundException {
		FileInputStream fin = new FileInputStream(loadfrom);
		ObjectInputStream objin = new ObjectInputStream(fin);
		Object obj = objin.readObject();
		System.out.println(obj.toString());
    	if (obj instanceof PairingParameters) {
			PairingParameters params = (PairingParameters) obj;
			this.pairingParams = params;
			this.p = PairingFactory.getPairing(this.pairingParams);
		}
    	obj = objin.readObject();
		System.out.println(obj.toString());
		if (obj instanceof List<?>) {
			List<byte[]> list = (List<byte[]>) obj;
			this.g = this.p.getG1().newElement();
			this.g.setFromBytes(list.get(0));
			System.out.println("g " + this.g.toString());
			this.gp = this.p.getG2().newElement();
			this.gp.setFromBytes(list.get(1));
			System.out.println("gp " + this.gp.toString());
			this.h = this.p.getG1().newElement();
			this.h.setFromBytes(list.get(2));
			System.out.println("h " + this.h.toString());
			this.f = this.p.getG1().newElement();
			this.f.setFromBytes(list.get(3));
			System.out.println("f " + this.f.toString());
			this.gAlpha = this.p.getGT().newElement();
			this.gAlpha.setFromBytes(list.get(4));
			System.out.println("gHatAlpha " + this.gAlpha.toString());
		}		
	}

	public CPabePublicParameters() {
	}

	public void saveAs(String saveas) throws IOException {
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(saveas));
		List<byte[]> list = new ArrayList<byte[]>();
		list.add(this.g.toBytes()); 		// 0
		list.add(this.gp.toBytes());		// 1
		list.add(this.h.toBytes());			// 2
		list.add(this.f.toBytes());			// 3
		list.add(this.gAlpha.toBytes());	// 4
		out.writeObject(this.pairingParams);
		out.writeObject(list);
	    out.close();		    
	}
	
	public String toString() {
		JSONObject obj = new JSONObject();
		JSONObject key = new JSONObject();
		key.put("g", this.g.toString());
		key.put("gp", this.gp.toString());
		key.put("gHatAlpha", this.gAlpha.toString());
		key.put("h", this.h.toString());
		key.put("f", this.f.toString());
		key.put("pairing", this.pairingParams.toString());
		//key.put("pairing", this.pairingParams.toString() );
		obj.put("name", "pk");
		obj.put("key", key);		
		return key.toJSONString();
	}
}
