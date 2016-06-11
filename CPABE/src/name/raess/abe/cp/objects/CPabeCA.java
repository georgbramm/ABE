package name.raess.abe.cp.objects;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;

import name.raess.abe.cp.CPabeSettings;

/* This Class represents a CA in a CP-ABE Scheme
 * it consists of a Master Secret Key (mk) and a
 * Public Parameters Key (pk)
 */
public class CPabeCA {
	// the public parameters key
	public CPabePublicParameters pk;
	
	// the master secret key
	public CPabeMasterSecret msk;
	
	// a constructor using an exisiting msk and pk
	public CPabeCA(CPabeMasterSecret msk, CPabePublicParameters pk) {
		this.msk = msk;
		this.pk = pk;
	}
	
	// a constructor without msk and pk
	public CPabeCA() {
	}	
	
	// return msk and pk as a string
	// seperated by new line
	public String toString() {
		String ret = "";
		if(CPabeSettings.consoleBase64) {
			try {
				ret = this.msk.exportBase64() + "\n" + this.pk.exportBase64();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return ret;
		}
		else {
			return this.msk.toString() + "\n" + this.pk.toString();
		}
		
	}
	
}
