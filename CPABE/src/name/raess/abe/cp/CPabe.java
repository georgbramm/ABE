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

	// a constructor using a msk and a pk in a file
	public CPabe(String cpabekeymsk, String cpabekeypk) throws ClassNotFoundException, IOException {
		CPabePublicParameters pk = new CPabePublicParameters(cpabekeypk);
		CPabeMasterSecret msk = new CPabeMasterSecret(cpabekeymsk, pk);
		this.ca = new CPabeCA(msk, pk);
		if(CPabeSettings.consoleKeyOutput) {
			// and give it out to console
			System.out.println(this.ca.toString());			
		}
	}

	// generate a fresh new ca
	public CPabe() {
		// generate a new CA upon construction
		CPabePublicParameters pk = new CPabePublicParameters();
		CPabeMasterSecret msk = new CPabeMasterSecret();		
		this.ca = CPabe.setup(pk, msk);
		if(CPabeSettings.consoleKeyOutput) {
			// and give it out to console
			System.out.println(this.ca.toString());			
		}
	}

	// Generate a public key and corresponding master secret key.
	public static CPabeCA setup(CPabePublicParameters pub, CPabeMasterSecret msk) {
		
		// local variables
		Element alpha, beta;

		// initialize curve & pairing
		TypeACurveGenerator curveGenerator = new TypeACurveGenerator(CPabeSettings.rBits, CPabeSettings.qBits);
		PairingParameters params = curveGenerator.generate();
		Pairing pairing = PairingFactory.getPairing(params);
		pub.pairingParams = params;
		pub.p = pairing;
		
		// initialize & compute local elements
		pub.g = pairing.getG1().newElement();
		pub.f = pairing.getG1().newElement();
		pub.h = pairing.getG1().newElement();
		pub.gp = pairing.getG2().newElement();
		pub.g_hat_alpha = pairing.getGT().newElement();
		alpha = pairing.getZr().newElement();
		msk.beta = pairing.getZr().newElement();
		msk.g_alpha = pairing.getG2().newElement();
		alpha.setToRandom();
		msk.beta.setToRandom();
		pub.g.setToRandom();
		pub.gp.setToRandom();
		msk.g_alpha = pub.gp.duplicate();
		msk.g_alpha.powZn(alpha);
		beta = msk.beta.duplicate();
		beta.invert();
		pub.f = pub.g.duplicate();
		pub.f.powZn(beta);
		pub.h = pub.g.duplicate();
		pub.h.powZn(msk.beta);
		pub.g_hat_alpha = pairing.pairing(pub.g, msk.g_alpha);
		
		// generate a new ca set keys and return
		CPabeCA ca = new CPabeCA();
		ca.msk = msk;
		ca.pk = pub;
		
		return ca;
	}

	/*
	 * Generate a private key with the given set of attributes.
	 */
	public static CPabeUserKey keygen(CPabePublicParameters pub, CPabeMasterSecret msk, String[] attrs)
			throws NoSuchAlgorithmException {
		
		CPabeUserKey prv = new CPabeUserKey();
		Element g_r, r, beta_inv;
		Pairing pairing;

		/* initialize */
		pairing = pub.p;
		prv.d = pairing.getG2().newElement();
		g_r = pairing.getG2().newElement();
		r = pairing.getZr().newElement();
		beta_inv = pairing.getZr().newElement();

		/* compute */
		r.setToRandom();
		g_r = pub.gp.duplicate();
		g_r.powZn(r);

		prv.d = msk.g_alpha.duplicate();
		prv.d.mul(g_r);
		beta_inv = msk.beta.duplicate();
		beta_inv.invert();
		prv.d.powZn(beta_inv);

		int i;
		prv.attributes = new ArrayList<CPabeUserAttribute>();
		for (i = 0; i < attrs.length; i++) {
			CPabeUserAttribute att = new CPabeUserAttribute();
			Element h_rp;
			Element rp;

			att.description = attrs[i];

			att.dj = pairing.getG2().newElement();
			att.djp = pairing.getG1().newElement();
			h_rp = pairing.getG2().newElement();
			rp = pairing.getZr().newElement();

			CPabeTools.randomOracle(h_rp, att.description);
			
			rp.setToRandom();

			h_rp.powZn(rp);

			att.dj = g_r.duplicate();
			att.dj.mul(h_rp);
			att.djp = pub.g.duplicate();
			att.djp.powZn(rp);

			prv.attributes.add(att);
		}

		return prv;
	}
	
	public static CPabeCipherText encrypt(CPabePublicParameters pub, byte[] message, JSONObject jsonPolicy) throws Exception {
		CPabeCipherText cph = new CPabeCipherText();
		Element s, m;

		/* initialize */

		Pairing pairing = pub.p;
		s = pairing.getZr().newElement();
		m = pairing.getGT().newElement();
		cph.cs = pairing.getGT().newElement();
		cph.c = pairing.getG1().newElement();
		
		cph.policy = CPabeTools.parsePolicy(jsonPolicy);

		System.out.println("policy:" + cph.policy.toString());
		
		/* compute */
		m.setToRandom();
		s.setToRandom();
		cph.cs = pub.g_hat_alpha.duplicate();
		cph.cs.powZn(s); /* num_exps++; */
		cph.cs.mul(m); /* num_muls++; */

		cph.c = pub.h.duplicate();
		cph.c.powZn(s); /* num_exps++; */

		CPabeTools.fillPolicy(cph.policy, pub, s);
		
		cph.cipherText = CPabeTools.symEncrypt(m, message);

		return cph;
	}

	/*
	 * Decrypt the specified ciphertext using the given private key, filling in
	 * the provided element m (which need not be initialized) with the result.
	 * 
	 * Returns true if decryption succeeded, false if this key does not satisfy
	 * the policy of the ciphertext (in which case m is unaltered).
	 */
	public static String decrypt(CPabePublicParameters pub, CPabeUserKey prv, CPabeCipherText cph) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		Element t;
		Element m;
		
		m = pub.p.getGT().newElement();
		t = pub.p.getGT().newElement();

		CPabeTools.checkSatisfy(cph.policy, prv);
		if (!cph.policy.satisfiable) {
			System.err.println("cannot decrypt, attributes in key do not satisfy policy");
			return "";
		}

		CPabeTools.pickSatisfyMinLeaves(cph.policy, prv);

		CPabeTools.decFlatten(t, cph.policy, prv, pub);

		m = cph.cs.duplicate();
		m.mul(t); /* num_muls++; */

		t = pub.p.pairing(cph.c, prv.d);
		t.invert();
		m.mul(t); /* num_muls++; */
		
		return CPabeTools.symDecrypt(m, cph);
	}

	public CPabeMasterSecret getMasterSecretKey() {
		return this.ca.msk;
	}

	public CPabePublicParameters getPublicParameters() {
		return this.ca.pk;
	}
}