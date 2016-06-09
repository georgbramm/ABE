package name.raess.abe.cp.objects;

import it.unisa.dia.gas.jpbc.Element;

public class CPabePolynomial {
	
	public int degree;			// degree of polynom
	public Element[] coef;		// all coefficients (degree+1)
	
	public CPabePolynomial() {
	}	
	
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
}
