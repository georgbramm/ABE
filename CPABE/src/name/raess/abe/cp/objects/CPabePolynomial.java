package name.raess.abe.cp.objects;

import it.unisa.dia.gas.jpbc.Element;

public class CPabePolynomial {
	
	public int degree;			// degree of polynom
	public Element[] coef;		// all coefficients (degree+1)
	
	public CPabePolynomial() {
	}	
	
	public CPabePolynomial(int d, Element zero) {
		this.degree = d;
		this.coef = new Element[d + 1];

		for (int i = 0; i < d + 1; i++) {
			this.coef[i] = zero.duplicate();
			this.coef[i].setToRandom();
		}
		this.coef[0].set(zero);
	}

	public static CPabePolynomial generateRandom(int degree, Element zeroVal) {
		CPabePolynomial q = new CPabePolynomial(degree, zeroVal);
		if(degree > 0) {
			for (int i = 1; i < degree; i++) {
				q.coef[i] = zeroVal.duplicate();
				q.coef[i].setToRandom();
			}
		}
		return q;
	}
	
	public Element evaluateAt(Element atPosition) {
		Element temp, one, result;
		temp = atPosition.duplicate();
		one = atPosition.duplicate();
		result = atPosition.duplicate();
		temp.setToZero();
		one.setToOne();
		result.setToZero();
		for (int i = 0; i < this.degree; i++) {
			temp = this.coef[i].duplicate();
			temp.mul(one); 
			result.add(temp);
			one.mul(atPosition);
		}
		return result;
	}
}
