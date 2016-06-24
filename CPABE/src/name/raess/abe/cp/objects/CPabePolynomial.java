package name.raess.abe.cp.objects;

import it.unisa.dia.gas.jpbc.Element;

public class CPabePolynomial {
	
	public int degree;			// degree of polynom
	public Element[] coef;		// all coefficients (degree+1)
	
	public CPabePolynomial(int degree, Element zeroVal) {
		this.degree = degree;
		this.coef = new Element[degree + 1];
		this.coef[0] = zeroVal.duplicate();
		this.coef[0].set(zeroVal);
		for (int i = 1; i < degree + 1; i++) {
			this.coef[i] = zeroVal.duplicate();
			this.coef[i].setToRandom();
		}
	}

	public Element evalPoly(Element x) {
		Element r = this.coef[0].duplicate();
		Element s = r.duplicate();
		Element t = r.duplicate();
		r.setToZero();
		t.setToOne();
		for (int i = 0; i < this.degree + 1; i++) {
			s = this.coef[i].duplicate();
			s.mul(t); 
			r.add(s);
			t.mul(x);
		}
		return r;
	}	
}
