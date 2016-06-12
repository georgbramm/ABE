package name.raess.abe.cp;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import name.raess.abe.cp.objects.CPabeCA;
import name.raess.abe.cp.objects.CPabeCipherText;
import name.raess.abe.cp.objects.CPabeMasterSecret;
import name.raess.abe.cp.objects.CPabePublicParameters;
import name.raess.abe.cp.objects.CPabeUserAttribute;
import name.raess.abe.cp.objects.CPabeUserKey;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import javax.crypto.NoSuchPaddingException;
import org.json.simple.JSONObject;


public class CPabe {
	
	// our ca
	private CPabeCA ca;
	
	/*
	 *  return the master secret key {msk}
	 *  
	 *  @return a CPabeMasterSecret Key
	 */
	public CPabeMasterSecret getMasterSecretKey() {
		return this.ca.msk;
	}

	/*
	 *  return the public parameters key {pk}
	 *  
	 *  @return a CPabePublicParameters Key
	 */
	public CPabePublicParameters getPublicParameters() {
		return this.ca.pk;
	}	
	
	/*
	 *  constructors a CPABE with a given cp-abe scheme using given {msk} and {pk} keys
	 *  (given as String paths to the file(s)). If CPabeSettings.consoleKeyOutput
	 *  is set to true the newly created key pair is printed to the console
	 *  
	 *  @param mskPath path to a msk file
	 *  @param pkPath path to a pk file
	 */
	public CPabe(String mskPath, String pkPath) throws ClassNotFoundException, IOException {
		// generate new {pk} and {msk} keys with files given as string path
		CPabePublicParameters pk = new CPabePublicParameters(pkPath);
		CPabeMasterSecret msk = new CPabeMasterSecret(mskPath, pk);
		// generate a new CA with a given key pair
		this.ca = new CPabeCA(msk, pk);
		// and give it out to console if desired
		if(CPabeSettings.consoleOutput) {
			System.out.println(this.ca.toString());			
		}
	}

	/*
	 *  constructors a CPABE with a new cp-abe scheme using a new {msk} and {pk} key.
	 *  If CPabeSettings.consoleKeyOutput is set to true the newly 
	 *  created key pair is printed to the console
	 */
	public CPabe() {
		// completely new {pk} and {msk} keys
		CPabePublicParameters pk = new CPabePublicParameters();
		CPabeMasterSecret msk = new CPabeMasterSecret();	
		// generate a completely new CA upon construction
		this.ca = CPabe.setup(pk, msk);
		// and give it out to console if desired
		if(CPabeSettings.consoleOutput) {
			System.out.println(this.ca.toString());			
		}
	}

	/*
	 *  constructors a new cp-abe scheme and calculate & generate new key pair {msk} and {pk}.
	 *  
	 *  @param pk a CPabePublicParameters object
	 *  @param msk a CPabeMasterSecret object
	 *  @return a newly generate CPabeCA
	 */
	public static CPabeCA setup(CPabePublicParameters pk, CPabeMasterSecret msk) {
		// initialize new curve & pairing
		TypeACurveGenerator curveGenerator = new TypeACurveGenerator(CPabeSettings.rBits, CPabeSettings.qBits);
		PairingParameters parms = curveGenerator.generate();
		Pairing pairing = PairingFactory.getPairing(parms);
		pk.pairingParams = parms;
		pk.p = pairing;
		
		// initialize & compute elements
		// Public Parameters Key {PK}
		// g
		pk.g = pk.p.getG1().newElement();
		pk.g.setToRandom();
		// h
		pk.h = pk.p.getG1().newElement();
		pk.h = pk.g.duplicate();
		// f
		pk.f = pk.p.getG1().newElement();
		pk.f = pk.g.duplicate();		
		// g pairing
		pk.gp = pk.p.getG2().newElement();
		pk.gp.setToRandom();
		// e(g, g)^alpha
		pk.gHatAlpha = pk.p.getGT().newElement();
		
		// Master Secret Key {MSK}
		// beta
		msk.beta = pk.p.getZr().newElement().setToRandom();	
		// alpha
		msk.gAlpha = pk.p.getG2().newElement();
		msk.gAlpha = pk.gp.duplicate();
		msk.gAlpha.powZn(pk.p.getZr().newElement().setToRandom());
		
		// and now after msk.beta is computed
		// apply msk.beta to {PK}->f^(1/beta)
		pk.f.powZn(msk.beta.invert());
		// apply msk.beta to {PK}->h^beta
		pk.h.powZn(msk.beta);	
		
		// Computes the product of pairings, 
		// that is 'e'('pk.g'[0], 'msk.gAlpha'[0]) ... 'e'('pk.g'[n-1], 'msk.gAlpha'[n-1]).
		pk.gHatAlpha = pairing.pairing(pk.g, msk.gAlpha);
		
		// generate a new ca set keys and return
		return new CPabeCA(msk, pk);
	}

	/*
	 *  calculate & generate a new user key {sk} with an attribute set, given as a String[] array
	 *  and a public parameters key {pk} and a master secret key {sk}
	 *  
	 *  @param pk a CPabePublicParameters object
	 *  @param msk a CPabeMasterSecret object
	 *  @param attrs an array of attributes as string values
	 *  @return a newly generate CPabeUserKey corresponding to the given attrs.
	 */
	public static CPabeUserKey keygen(CPabePublicParameters pk, CPabeMasterSecret msk, String[] attris)
			throws NoSuchAlgorithmException {
		
		// new user key
		CPabeUserKey prv = new CPabeUserKey();	
		
		// random r
		Element r;
		r = pk.p.getZr().newElement();
		r.setToRandom();
		
		// calc & set new D
		Element dgPrime;
		dgPrime = pk.p.getG2().newElement();
		dgPrime = pk.gp.duplicate();
		dgPrime.powZn(r);		
		prv.d = pk.p.getG2().newElement();
		prv.d = msk.gAlpha.duplicate();
		prv.d.mul(dgPrime);
		prv.d.powZn(msk.beta.invert());
		
		// convert singular attributes with value to a multiple attribute
		String[] convertedAttributes = CPabeTools.convertValueAttributes(attris);
		
		// generate a new list of CPabeUserAttributes
		prv.attributes = new ArrayList<CPabeUserAttribute>();
		for (int i = 0; i < convertedAttributes.length; i++) {
			
			// random rj
			Element rj = pk.p.getZr().newElement().setToRandom();
			
			// hashed attribute element generated by a random oracle
			// using the attribute as string
			Element hashedAttribute = pk.p.getG2().newElement();
			CPabeTools.randomOracle(hashedAttribute, convertedAttributes[i]);
			
			// calc H(j)^r_j
			hashedAttribute.powZn(rj);
			
			// a new user attribute
			CPabeUserAttribute att = new CPabeUserAttribute();
			
			// set description string
			att.description = convertedAttributes[i];
			
			// calc & set Dj part
			att.dj = pk.p.getG2().newElement();
			att.dj = dgPrime.duplicate();
			att.dj.mul(hashedAttribute);
			
			// calc & set Dj prime part
			att.djp = pk.p.getG1().newElement();
			att.djp = pk.g.duplicate();
			att.djp.powZn(rj);
			
			// add to attributes list of {SK}
			prv.attributes.add(att);
		}
		
		// and return {SK}
		return prv;
	}
	
	/*
	 *  encrypt a byte[] message using the public parameters {pk} and a 
	 *  policy given as JSONObject.
	 *  
	 *  {rules}:
	 *   TODO: WRITE DOWN RULES
	 *  
	 *  @param pk a CPabePublicParameters object
	 *  @param message a byte[] message to encrypt
	 *  @param jsonPolicy a JSONObject policy structure according to the {rules}
	 *  @return a newly generate CPabeCipherText corresponding to given data and the JSONObject policy.
	 */	
	public static CPabeCipherText encrypt(CPabePublicParameters pk, byte[] message, JSONObject jsonPolicy) throws Exception {
		
		// new ciphertext
		CPabeCipherText ct = new CPabeCipherText();
		
		// initialize random Elements
		Element s, m;
		s = pk.p.getZr().newElement();
		s.setToRandom();
		m = pk.p.getGT().newElement();
		m.setToRandom();
		
		// set C Prime part
		ct.cPrime = pk.p.getGT().newElement();
		ct.cPrime = pk.gHatAlpha.duplicate();
		ct.cPrime.powZn(s);
		ct.cPrime.mul(m);		
		
		// set C part
		ct.c = pk.p.getG1().newElement();
		ct.c = pk.h.duplicate();
		ct.c.powZn(s);
		
		// generate new policy tree 
		ct.policy = CPabeTools.parsePolicy(jsonPolicy);
		
		// and give it out to console if desired
		if(CPabeSettings.consoleOutput) {
			System.out.println(ct.policy.toDetail(true));
		}
		
		// calculate policy tree secret ( Bethencourt Goyal Algorithm ) 
		CPabeTools.bethencourtGoyal(ct.policy, pk, s);
		
		// encrypt byte message using random m
		ct.cipherText = CPabeTools.symEncrypt(m, message);

		// and return ciphertext
		return ct;
	}
	
	/*
	 *  decrypt a CPabeCipherText {ct} using the public parameters keys {pk} and a CPabeUserKey {sk}
	 *  
	 *  @param pk a CPabePublicParameters object
	 *  @param sk a CPabeUserKey object
	 *  @param ct a CPabeCipherText object
	 *  @return the decrypted
	 */		
	public static byte[] decrypt(CPabePublicParameters pk, CPabeUserKey sk, CPabeCipherText ct) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {

		// random m to recover from {ct}->C Prime
		Element m = pk.p.getGT().newElement();
		m = ct.cPrime.duplicate();
		
		// if the attributes in {sk} to not math the {ct}->policy return with null and msg to console
		if (!CPabeTools.checkSatisfy(ct.policy, sk)) {
			System.err.println("cannot decrypt, attributes in key do not satisfy policy");
			return null;
		}
		//otherwise
		else {
			// calculate min leaves
			CPabeTools.calculateMinLeaves(ct.policy, sk);
			Element one = pk.p.getZr().newElement().setToOne();
			// and root secret of bethencourt goyal tree (A)
			Element A = CPabeTools.decPolicyTree(ct.policy, sk, pk, one);
			// and multiply with cPrime and (1/e(C,D))
			m.mul(A);
			m.mul(pk.p.pairing(ct.c, sk.d).invert());
			// now we have decrypted the abe scheme (and hence m). we can now aes-decrypt the base64 ciphertext
			// using m.
			return CPabeTools.symDecrypt(m, ct);
		}
	}
	
	// TODO (DELEGATE)
}