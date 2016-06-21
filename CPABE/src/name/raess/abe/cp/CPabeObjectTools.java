package name.raess.abe.cp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;

public class CPabeObjectTools {
	// this converts an Object into byte[]
	public static byte[] convertToBytes(Object object) throws IOException {
	    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
	         ObjectOutput out = new ObjectOutputStream(bos)) {
	        out.writeObject(object);
	        return bos.toByteArray();
	    } 
	}
	// this converts byte[] into an Object
	public static Object convertFromBytes(byte[] bytes) throws IOException, ClassNotFoundException {
	    try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
	         ObjectInput in = new ObjectInputStream(bis)) {
	        return in.readObject();
	    } 
	}
	// encode a string in base64 using apaches library
	public static byte[] b64decode(String g) {
		return org.apache.commons.codec.binary.Base64.decodeBase64(g);
	}
	// decode a string from base64 using apaches library
	public static String b64encode(byte[] g) {
		return org.apache.commons.codec.binary.Base64.encodeBase64String(g);
	}
}
