package name.raess.abe;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

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
    public static void main(String[] args) throws NoSuchAlgorithmException, ParseException, InvalidAlgorithmParameterException, IOException, ClassNotFoundException {

    	
    	// Start new CPabe
        CPabe cp = new CPabe();
    	
    	// Load an existing CPabe
        //CPabe cp = new CPabe(CPabeSettings.CPabeKeyMSK, CPabeSettings.CPabeKeyPK);
        
        // and save msk
        cp.getMasterSecretKey().saveAs(CPabeSettings.CPabeKeyMSK);
        // and save pk
        cp.getPublicParameters().saveAs(CPabeSettings.CPabeKeyPK);
                        
        String[] attributes = new String[2];
        attributes[0] = "test";
        attributes[1] = "raess";
		CPabeUserKey georgsKey = CPabe.keygen(cp.getPublicParameters(), cp.getMasterSecretKey(), attributes);
		
		georgsKey.saveAs(CPabeSettings.CPabeKeySK.replace("$username", "georg"));
		
		try {
			/* example 1
			// {"or":[{"att":"A","val":"5"},{"att":"B"},{"and":[{"att":"C"},{"att":"D"}]}]}
			String sJSON = "{\"or\":[{\"att\":\"A\",\"val\":\"5\"},{\"att\":\"B\"},{\"and\":[{\"att\":\"C\"},{\"att\":\"D\"}]}]}";
			JSONObject json = (JSONObject) new JSONParser().parse(sJSON);
			CPabePolicy treePolicy = CPabeTools.toPolicy(json);
			System.out.println(treePolicy.toString()); */
			String sJSONenc = "{\"and\":[{\"att\":\"raess\"},{\"att\":\"test\"}]}";
			JSONObject jsonEnc = (JSONObject) new JSONParser().parse(sJSONenc);
			CPabeCipherText ct = cp.encrypt(cp.getPublicParameters(), "hi there".getBytes(), jsonEnc);
			//System.out.println(ct.toString());
			System.out.println(cp.decrypt(cp.getPublicParameters(), georgsKey, ct));
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
