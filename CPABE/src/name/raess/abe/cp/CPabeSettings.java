package name.raess.abe.cp;

public class CPabeSettings {

	// configuration
	public static final String version = "0.0.1";
	public static final String versionString = "Version: " + version + "\n";
	public static final int rBits = 128;
	public static final int qBits = 512;
	public static final boolean consoleOutput = true;
	public static final boolean consoleDetails = false;
	
	// key file names
	public static final String CPabeKeyMSK = "keys/abe-msk";
	public static final String CPabeKeyPK = "keys/abe-pk";
	public static final String CPabeKeySK = "keys/abe-sk-$username";
	
	// split string for aes encryption
	public static final String SPLIT = "---- SPLIT ----\n";
	
	// uppercase variables in json structure 
	public static final String OR = "OR";
	public static final String AND = "AND";
	public static final String OF = "OF";
	public static final String ATT = "ATT";
	public static final String VAL = "VAL";
	public static final String EQ = "=";
	public static final String LT = "<";
	public static final String GT = ">";
	public static final String LTEQ = "<=";
	public static final String GTEQ = ">=";
}
