package name.raess.abe.cp;

public class CPabeSettings {
	
	

	// configuration
	public static final String version = "0.0.2";
	public static final String versionString = "Version: jCP-ABE " + version + "\n";
	public static final int rBits = 128;
	public static final int qBits = 512;
	public static final boolean consoleOutput = false;
	public static final boolean consoleBase64 = false;
	
	// key file names
	public static final String CPabeKeyMSK = "keys/abe-msk";
	public static final String CPabeKeyPK = "keys/abe-pk";
	public static final String CPabeKeySK = "keys/abe-sk-$username";
	
	public static class CPabeConstants {
		
		// split string for AES encryption
		public static final String SPLIT = "\n---- AES SPLIT ----\n";
		
		// abe attribute value split
		public static final String AVSPLIT = "@@";
		
		// key export header & tails
		public static final String NEWLINE = System.getProperty("line.separator");
		public static final String PKHEAD = "-----BEGIN CPABE PUBLIC KEY BLOCK-----" + NEWLINE;
		public static final String PKTAIL = NEWLINE + "-----END CPABE PUBLIC KEY BLOCK-----";
		public static final String MSKHEAD = "-----BEGIN CPABE MASTER KEY BLOCK-----" + NEWLINE;
		public static final String MSKTAIL = NEWLINE + "-----END CPABE MASTER KEY BLOCK-----";
		public static final String SKHEAD = "-----BEGIN CPABE USER KEY BLOCK-----" + NEWLINE;
		public static final String SKTAIL = NEWLINE + "-----END CPABE USER KEY BLOCK-----";	
		public static final String CTHEAD = "-----BEGIN CPABE CIPHERTEXT BLOCK-----" + NEWLINE;
		public static final String CTTAIL = NEWLINE + "-----END CPABE CIPHERTEXT BLOCK-----";	
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
		
		// lowercase variables in scheme
	}
}
