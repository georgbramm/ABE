package name.raess.abe.console;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import name.raess.abe.cp.CPabe;
import name.raess.abe.cp.CPabeTools;
import name.raess.abe.cp.objects.CPabeCipherText;
import name.raess.abe.cp.objects.CPabePublicParameters;
import name.raess.abe.cp.objects.CPabeUserKey;

public class console {
	public static void main ( String [] arguments ) {
		String msk = "";
		String pk = "";
		String sk = "";
		String ct = "";
		String json = "";
		if(arguments.length > 2) {
			if(arguments[0].equals("setup")) {
				try {
					CPabe cp = new CPabe();
					writeTextFile(arguments[1], cp.getMasterSecretKey().exportBase64());
					writeTextFile(arguments[2], cp.getPublicParameters().exportBase64());
				} catch (IOException e) {
					System.out.println("error: io exception");
					e.printStackTrace();
				}
			}
			else if(arguments[0].equals("keygen")) {
				msk = readTextFile(arguments[1]);
				pk = readTextFile(arguments[2]);
				String[] attributes = new String[arguments.length - 4];
			    for(int i = 0; i < arguments.length - 4; i++) {
			    	attributes[i] = arguments[i + 4];
			    }
				try {
					CPabe cp = new CPabe();
					cp.getPublicParameters().importBase64(pk);
					cp.getMasterSecretKey().importBase64(msk, cp.getPublicParameters());
					CPabeUserKey userKey = CPabe.keygen(cp.getPublicParameters(), cp.getMasterSecretKey(), attributes);
					writeTextFile(arguments[3], userKey.exportBase64());
				} catch (ClassNotFoundException | IOException | NoSuchAlgorithmException e) {
					e.printStackTrace();
				}
			}
			else if (arguments[0].equals("encrypt")) {
				pk = readTextFile(arguments[1]);
				CPabePublicParameters ppk = new CPabePublicParameters();
				try {
					ppk.importBase64(pk);
					Path path = Paths.get(arguments[2]);
					System.out.println(arguments[3]);
					JSONObject jsonEnc = (JSONObject) new JSONParser().parse(arguments[3]);
					boolean test = CPabeTools.validatePolicy(jsonEnc);
					if(test) {
						CPabeCipherText cct = CPabe.encrypt(ppk, Files.readAllBytes(path), jsonEnc);
						writeTextFile(arguments[2] + ".abe", cct.exportBase64());
					}
					else {
						System.out.println("error: sorry the json policy " + arguments[3] + " is not valid.");
					}
				} catch (Exception e1) {
					e1.printStackTrace();
				}
			}
			else if (arguments[0].equals("decrypt")) {
				pk = readTextFile(arguments[1]);
				sk = readTextFile(arguments[2]);
				ct = readTextFile(arguments[3]);
				CPabePublicParameters ppk = new CPabePublicParameters();
				CPabeUserKey ssk = new CPabeUserKey();
				try {
					ppk.importBase64(pk);
					ssk.importBase64(sk, ppk);
					CPabeCipherText cct = new CPabeCipherText();
					cct.importBase64(ct, ppk);
					byte[] data = CPabe.decrypt(ppk, ssk, cct);
					FileOutputStream fos = new FileOutputStream(arguments[3].substring(0,arguments[3].length()-4));
					fos.write(data);
					fos.close();
				} catch (Exception e1) {
					e1.printStackTrace();
				}
			}
			else {
				System.out.println("error: unknown parameter '"+arguments[0]+"'");
			}
		}
		else {
			System.out.println("usage:\n------");
			System.out.println("1) generate a new scheme:");
			System.out.println("   java -jar "+System.getProperty("java.class.path")+" setup [msk] [pk]\n");
			System.out.println("2) generate a new key:");
			System.out.println("   java -jar "+System.getProperty("java.class.path")+" keygen [msk] [pk] [sk] [attributes]\n");
			System.out.println("3) encrypt a file:");
			System.out.println("   java -jar "+System.getProperty("java.class.path")+" encrypt [pk] [file] [policy]\n");
			System.out.println("4) decrypt a file:");
			System.out.println("   java -jar "+System.getProperty("java.class.path")+" decrypt [pk] [sk] [file]\n");
			System.out.println("where:");
			System.out.println("[msk] is the path to the master secret key");
			System.out.println("[pk] is the path to the public parameters key");
			System.out.println("[sk] is the path to the user key");
			System.out.println("[file] is the path to a file on the system.");
			System.out.println("[policy] is the json policy as String.");
			System.out.println("[attributes] is a list of attributes separated by a blank/space character.");
		}
	}
	
	private static String readTextFile(String file) {
		try(BufferedReader br = new BufferedReader(new FileReader(file))) {
		    StringBuilder sb = new StringBuilder();
		    String line = br.readLine();
		    while (line != null) {
		        sb.append(line);
		        sb.append(System.lineSeparator());
		        line = br.readLine();
		    }
		    return sb.toString();
		} catch (FileNotFoundException e) {
			System.out.println("error: the file '" + file + "' was not found.");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("error: could not read the file '" + file + "'.");
			e.printStackTrace();
		}
		return "";
	}
	
	private static void writeTextFile(String file, String data) {
		try {
			PrintWriter writer = new PrintWriter(new FileWriter(file));
			writer.print(data); 
			writer.close();
			System.out.println(data + "\nsaved as: " + file);
		} catch (IOException e) {
			System.out.println("error: could not write to file " + file);
			e.printStackTrace();
		}
	}
}
