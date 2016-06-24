 
package name.raess.abe.cp.objects;

import java.util.Comparator;

public class CPabeMinLeavesComparator implements Comparator<Integer> {
	CPabePolicy policy;
	public CPabeMinLeavesComparator(CPabePolicy p) {
		this.policy = p;
	}
	public int compare(Integer x, Integer y) {
		if(this.policy.children[x.intValue()].minLeaves > this.policy.children[y.intValue()].minLeaves) {
			return 1;
		}
		else if(this.policy.children[x.intValue()].minLeaves == this.policy.children[y.intValue()].minLeaves) {
			return 0;
		}	
		else {
			return -1;
		}
	}

}
