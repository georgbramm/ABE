package name.raess.abe.console;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;

import name.raess.abe.cp.CPabe;
import name.raess.abe.cp.objects.CPabeUserKey;

public class console {
	public static void main ( String [] arguments ) {
		String msk = "";
		String pk = "";
		if(arguments.length > 2) {
			if(arguments[0].equals("setup")) {
				try {
					PrintWriter mskWriter = new PrintWriter(new FileWriter(arguments[1]));
					try {
						PrintWriter pkWriter = new PrintWriter(new FileWriter(arguments[2]));
						CPabe cp = new CPabe();
						mskWriter.print(cp.getMasterSecretKey().exportBase64()); 
						mskWriter.close();
						pkWriter.print(cp.getPublicParameters().exportBase64()); 
						pkWriter.close();
						System.out.println("[msk] saved as: " + arguments[1]);
						System.out.println("[pk] saved as: " + arguments[2]);
						
					} catch (IOException e) {
						System.out.println("error: could not write [pk] to file " + arguments[2]);
						e.printStackTrace();
					}
				} catch (IOException e) {
					System.out.println("error: could not write [msk] to file " + arguments[1]);
					e.printStackTrace();
				}
			}
			else if(arguments[0].equals("keygen")) {
				try(BufferedReader br = new BufferedReader(new FileReader(arguments[1]))) {
				    StringBuilder sb = new StringBuilder();
				    String line = br.readLine();
				    while (line != null) {
				        sb.append(line);
				        sb.append(System.lineSeparator());
				        line = br.readLine();
				    }
				    msk = sb.toString();
				} catch (FileNotFoundException e) {
					System.out.println("error: the [msk] file '" + arguments[1] + "' was not found.");
					e.printStackTrace();
				} catch (IOException e) {
					System.out.println("error: could not read the [msk] file '" + arguments[1] + "'.");
					e.printStackTrace();
				}
				try(BufferedReader br = new BufferedReader(new FileReader(arguments[2]))) {
				    StringBuilder sb = new StringBuilder();
				    String line = br.readLine();
				    while (line != null) {
				        sb.append(line);
				        sb.append(System.lineSeparator());
				        line = br.readLine();
				    }
				    pk = sb.toString();
				} catch (FileNotFoundException e) {
					System.out.println("error: the [pk] file '" + arguments[2] + "' was not found.");
					e.printStackTrace();
				} catch (IOException e) {
					System.out.println("error: could not read the [pk] file '" + arguments[2] + "'.");
					e.printStackTrace();
				}
				String[] attributes = new String[arguments.length - 4];
			    for(int i = 0; i < arguments.length - 4; i++) {
			    	attributes[i] = arguments[i + 4];
			    }
		        try {
		        	CPabe cp = new CPabe();
					cp.getPublicParameters().importBase64(pk);
					cp.getMasterSecretKey().importBase64(msk, cp.getPublicParameters());
					try {
						CPabeUserKey userKey = CPabe.keygen(cp.getPublicParameters(), cp.getMasterSecretKey(), attributes);
					    try {
							PrintWriter skWriter = new PrintWriter(new FileWriter(arguments[3]));
							skWriter.print(userKey.exportBase64()); 
							skWriter.close();
							System.out.println("[sk] saved as: " + arguments[3]);
						} catch (IOException e) {
							System.out.println("error: could not write [sk] to file " + arguments[3]);
							e.printStackTrace();
						}
					} catch (NoSuchAlgorithmException e1) {
						System.out.println("error: NoSuchAlgorithmException while generating a new key.");
						e1.printStackTrace();
					} 
				} catch (ClassNotFoundException | IOException e1) {
					System.out.println("error: ClassNotFoundException while generating a new key.");
					e1.printStackTrace();
				}
			}
			else {
				System.out.println("error: unknown parameter '"+arguments[0]+"'");
			}
		}
		else {
			System.out.println("usage:");
			System.out.println("------");
			System.out.println("1) generate a new scheme:");
			System.out.println("   java -jar console.jar setup [msk] [pk]");
			System.out.println();
			System.out.println("2) generate a new key:");
			System.out.println("   java -jar console.jar keygen [msk] [pk] [sk] [attributes]");
			System.out.println();
			System.out.println("where:");
			System.out.println("[msk] is the path to the master secret key");
			System.out.println("[pk] is the path to the public parameters key");
			System.out.println("[sk] is the path to the user key");
			System.out.println("[attributes] is a list of attributes separated by a blank/space character.");
		}
	}
}
