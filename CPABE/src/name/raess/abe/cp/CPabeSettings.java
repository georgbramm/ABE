package name.raess.abe.cp;

public class CPabeSettings {

	// configuration
	public static final String version = "0.0.1";
	public static final String versionString = "Version: " + version + "\n";
	public static final int rBits = 128;
	public static final int qBits = 512;
	public static final boolean consoleKeyOutput = true;
	
	// key file names
	public static final String CPabeKeyMSK = "keys/abe-msk";
	public static final String CPabeKeyPK = "keys/abe-pk";
	public static final String CPabeKeySK = "keys/abe-sk-$username";
	
	// key header
	public static final String CPabeMSKhead = "---- BEGIN CPABE MSK ----\n";
	public static final String CPabePKhead = "---- BEGIN CPABE PK ----\n";
	
	// key footer
	public static final String CPabeMSKtail = "---- END CPABE MSK ----\n";
	public static final String CPabePKtail = "---- END CPABE PK ----\n";
	
	public static final String SPLIT = "---- SPLIT ----\n";
	
	public static final String OR = "OR";
	public static final String AND = "AND";
	public static final String OF = "OF";
	public static final String ATT = "ATT";
	public static final String VAL = "VAL";
	public static final String EQ = "=";
	
}
