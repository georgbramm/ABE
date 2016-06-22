package name.raess.abe.cp.objects;

import java.io.IOException;
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
	public String exportBase64() throws IOException {
		return this.msk.exportBase64() 
				+ CPabeSettings.CPabeConstants.NEWLINE
				+ this.pk.exportBase64();
	}
	// return msk and pk as a string
	// seperated by new line
	public String toString() {
		try {
			return this.msk.exportBase64() + "\n" + this.pk.exportBase64();
		} catch (IOException e) {
			e.printStackTrace();
			return "";
		}
	}
	
}
