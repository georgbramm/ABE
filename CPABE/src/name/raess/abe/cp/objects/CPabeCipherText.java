package name.raess.abe.cp.objects;

import java.util.ArrayList;
import java.util.List;

import it.unisa.dia.gas.jpbc.Element;

public class CPabeCipherText {
	public CPabePolicy policy;
	public Element c;			// G1
	public Element cs;			// GT
	public String cipherText;
}
