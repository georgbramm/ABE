package name.raess.abe;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import name.raess.abe.cp.CPabe;
import name.raess.abe.cp.CPabeSettings;
import name.raess.abe.cp.objects.CPabeCipherText;
import name.raess.abe.cp.objects.CPabeUserKey;

class Start {
    @SuppressWarnings("static-access")
	public static void main(String[] args) throws NoSuchAlgorithmException, ParseException, InvalidAlgorithmParameterException, IOException, ClassNotFoundException {
    	
    	// Start new CPabe
        //CPabe cp = new CPabe();
    	
    	// Load an existing CPabe
        CPabe cp = new CPabe(CPabeSettings.CPabeKeyMSK, CPabeSettings.CPabeKeyPK);
        
        // and save msk
        cp.getMasterSecretKey().saveAs(CPabeSettings.CPabeKeyMSK);
        // and save pk
        cp.getPublicParameters().saveAs(CPabeSettings.CPabeKeyPK);
        
        cp.getPublicParameters().importBase64(cp.getPublicParameters().exportBase64());
        
        cp.getMasterSecretKey().importBase64(cp.getMasterSecretKey().exportBase64(), cp.getPublicParameters());
                     
        //long date = new Date().getTime() / 1000;
        
        String[] attributes = new String[3];
        attributes[0] = "raess";
        attributes[1] = "georg";
        attributes[2] = "date=-77";
        
		CPabeUserKey georgsKey = CPabe.keygen(cp.getPublicParameters(), cp.getMasterSecretKey(), attributes);
		georgsKey.saveAs(CPabeSettings.CPabeKeySK.replace("$username", "georg"));
		georgsKey.importBase64(georgsKey.exportBase64(), cp.getPublicParameters());
        //CPabeUserKey georgsKey = new CPabeUserKey("keys/abe-sk-georg", cp.getPublicParameters());
		
		try {

			String sJSONenc = "{\"and\":[{\"gt\":{\"att\":\"date\", \"val\":\"-100\"}},{\"att\":\"georg\"}]}";
			JSONObject jsonEnc = (JSONObject) new JSONParser().parse(sJSONenc);
			CPabeCipherText ct = cp.encrypt(cp.getPublicParameters(), "hi there".getBytes(), jsonEnc);
			System.out.println(new String(cp.decrypt(cp.getPublicParameters(), georgsKey, ct)));
			
		} catch (IOException e) {
			System.out.println("error parsing policy");
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}
