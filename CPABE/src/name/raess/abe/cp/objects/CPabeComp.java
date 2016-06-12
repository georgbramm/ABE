 
package name.raess.abe.cp.objects;

import java.util.Comparator;

public class CPabeComp implements Comparator<Integer> {

	CPabePolicy policy;
	
	public CPabeComp(CPabePolicy p) {
		this.policy = p;
	}

	@Override
	public int compare(Integer x, Integer y) {
		int a = policy.children[x.intValue()].minLeaves;
		int b = policy.children[y.intValue()].minLeaves;
		if(a < b) {
			return -1;
		}
		else if(a == b) {
			return 0;
		}	
		else {
			return 1;
		}
	}

}
