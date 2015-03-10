package org.apache.tomcat.dbcp.dbcp.ext;

import org.apache.tomcat.dbcp.dbcp.ext.CipherEncrypter;

public class Tool {    
    
	//"java -jar tomat-dbcp-ext.jar [e/d] [msg]"
    public static void main(String[] args) {
    	if (args.length != 2) {
    		System.out.println("Tomcat dbcp encrypt lib.");
    		System.exit(0);
    	}
    	CipherEncrypter c = new CipherEncrypter("EncryptDatasourceFactory", "AES");
    	if (args[0].equalsIgnoreCase("e")) {
    		System.out.println("enc: " + c.md5Enc(args[1]));
    	} else {
    		System.out.println("dec: " + c.md5Dec(args[1]));
    	}
    }
}
