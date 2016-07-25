package name.raess.abe.cp;

public class CPabeSettings {
	// abe configuration
	public static final String version = "0.0.3";
	public static final String versionString = "version: jCP-ABE " + version + "\n";
	public static final int rBits = 8;
	public static final int qBits = 1024;
	public static final boolean consoleOutput = false;
	// file names
	public static final String CPabeKeyMSK = "keys/abe-msk";
	public static final String CPabeKeyPK = "keys/abe-pk";
	public static final String CPabeKeyCT = "keys/abe-ct";
	public static final String CPabeKeySK = "keys/abe-sk-$username";
	
	public static class CPabeConstants {
		// abe attribute-value split
		public static final String SIGN = "@:";
		// key export header & tail
		public static final String NEWLINE = System.getProperty("line.separator");
		public static final String HEAD = "-----BEGIN CPABE " + SIGN + " BLOCK-----" + NEWLINE;
		public static final String TAIL = NEWLINE + "-----END CPABE " + SIGN + " BLOCK-----";
		public static final String MSK = "ENCRYPTED MASTER KEY";
		public static final String PK = "PUBLIC KEY";
		public static final String CT = "CIPHER TEXT";
		public static final String SK = "USER KEY";
		public static final int CHARSPERLINE = 64;
		
		// uppercase policy variables in json structure 
		public static final String OR = "OR";
		public static final String AND = "AND";
		public static final String OF = "OF";
		public static final String ATT = "ATT";
		public static final String VAL = "VAL";
		public static final String EQ = "EQ";
		public static final String LT = "LT";
		public static final String GT = "GT";
		public static final String LTEQ = "LTEQ";
		public static final String GTEQ = "GTEQ";
	}
}
