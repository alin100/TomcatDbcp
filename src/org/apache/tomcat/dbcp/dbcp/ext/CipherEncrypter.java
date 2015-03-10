package org.apache.tomcat.dbcp.dbcp.ext;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.tomcat.dbcp.dbcp.ext.CipherEncrypter;

public class CipherEncrypter {

    private final String HEXES = "0123456789ABCDEF";
    private final String SHARED_KEY;
    private final String ALGORITHM;

    /**
     *
     * @param salt can be null.
     * @param algorithm can be null.
     */
    public CipherEncrypter(String salt, String algorithm) {
        this.SHARED_KEY = (salt == null || salt.equals(""))
                ? "BAC464B197083AE82E0897E3D8388EE06CB3EF7BCFFF458" : salt;
        this.ALGORITHM = (algorithm == null || algorithm.equals(""))
                ? "AES" : algorithm;
    }

    /**
     *
     * @return SecretKey
     * @throws Exception
     */
    public SecretKey randomKey() {
        byte[] encoded = null;

        try {
            KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM);
            generator.init(128); // 192 and 256 bits may not be available
            SecretKey key = generator.generateKey();
            encoded = key.getEncoded();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CipherEncrypter.class.getName()).log(Level.SEVERE, null, ex);
        }

        return new SecretKeySpec(encoded, ALGORITHM);
    }

    /**
     *
     * @return SecretKey
     * @throws Exception
     */
    public SecretKey statickey() {
        byte[] passwordData = null;

        try {
            MessageDigest digester = MessageDigest.getInstance("MD5");
            char[] password = SHARED_KEY.toCharArray();

            for (char word : password) {
                digester.update((byte) word);
            }

            passwordData = digester.digest();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CipherEncrypter.class.getName()).log(Level.SEVERE, null, ex);
        }

        return new SecretKeySpec(passwordData, ALGORITHM);
    }

    /**
     *
     * @param spec
     * @param msg
     * @return byte[]
     * @throws Exception
     */
    public byte[] encryptToByte(SecretKey spec, String msg) {
        byte[] encrypt = null;

        try {
            Cipher eCipher = Cipher.getInstance(ALGORITHM);
            eCipher.init(Cipher.ENCRYPT_MODE, spec);
            encrypt = eCipher.doFinal(msg.getBytes());
        } catch (Exception ex) {
            Logger.getLogger(CipherEncrypter.class.getName()).log(Level.SEVERE, null, ex);
        }

        return encrypt;
    }

    /**
     * Decrypt a byte array.
     *
     * @param spec
     * @param encrypt
     * @return byte[]
     * @throws Exception
     */
    public byte[] decryptToByte(SecretKey spec, byte[] encrypt) {
        byte[] decrypt = null;

        try {
            Cipher dCipher = Cipher.getInstance(ALGORITHM);
            dCipher.init(Cipher.DECRYPT_MODE, spec);
            decrypt = dCipher.doFinal(encrypt);

        } catch (Exception ex) {
            Logger.getLogger(CipherEncrypter.class.getName()).log(Level.SEVERE, null, ex);
        }

        return decrypt;
    }

    /**
     *
     * @param spec
     * @param msg
     * @return String
     * @throws Exception
     */
    public String encrypt(SecretKey spec, String msg) {
        byte[] encrypt = this.encryptToByte(spec, msg);
        return toHex(encrypt);
    }

    /**
     * Decrypt a given String.
     *
     * @param spec
     * @param encrypt
     * @return String
     * @throws Exception
     */
    public String decrypt(SecretKey spec, String encrypt) {
        byte[] decrypt = this.decryptToByte(spec, toByte(encrypt));
        return new String(decrypt);
    }

    /**
     *  This method returns all available services types.
     *
     * @return String[]
     */
    public static String[] getServiceTypes() {
        Set<String> result = new HashSet<String>();
        // All all providers
        Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {
            // Get services provided by each provider
            Set keys = providers[i].keySet();
            for (Iterator it = keys.iterator(); it.hasNext();) {
                String key = (String) it.next();
                key = key.split(" ")[0];
                if (key.startsWith("Alg.Alias.")) {
                    // Strip the alias
                    key = key.substring(10);
                }
                int ix = key.indexOf('.');
                result.add(key.substring(0, ix));
            }
        }
        return (String[]) result.toArray(new String[result.size()]);
    }

    /**
     * This method returns the available implementations for a service type.
     *
     * @param serviceType
     * @return String[]
     */
    public static String[] getCryptoImpls(String serviceType) {
        Set<String> result = new HashSet<String>();
        // All all providers
        Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {
            // Get services provided by each provider
            Set keys = providers[i].keySet();
            for (Iterator it = keys.iterator(); it.hasNext();) {
                String key = (String) it.next();
                key = key.split(" ")[0];
                if (key.startsWith(serviceType + ".")) {
                    result.add(key.substring(serviceType.length() + 1));
                } else if (key.startsWith("Alg.Alias." + serviceType + ".")) {
                    // This is an alias
                    result.add(key.substring(serviceType.length() + 11));
                }
            }
        }
        return (String[]) result.toArray(new String[result.size()]);
    }

    /**
     * Iterator over all Services and it own implementations.
     * 
     * @return Map<String, String[]>
     */
    public static Map<String, String[]> treeService() {
        // Conteiner
        Map<String, String[]> map = new LinkedHashMap<String, String[]>();

        // List all available services types
        String[] serviceTypes = getServiceTypes();

        for (String service : serviceTypes) {
            // List the available implementations for a service type
            String[] implementations = getCryptoImpls(service);

            //Save the pair
            map.put(service, implementations);
        }

        return map;
    }

    /**
     * Print the tree
     */
    public static void displayTree() {
        Map<String, String[]> map = treeService();
        Set<String> servicesTypes = map.keySet();

        for (String service : servicesTypes) {
            System.out.println("\n||--" + service + "--||");
            String[] implementations = map.get(service);

            for (String crypt : implementations) {
                System.out.println(crypt);
            }
        }
    }

    private String toHex(byte[] raw) {
        if (raw == null) {
            return null;
        }

        final StringBuilder hex = new StringBuilder(2 * raw.length);

        for (final byte b : raw) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
        }

        return hex.toString();
    }

    private byte[] toByte(String hex) {
        byte[] bts = new byte[hex.length() / 2];

        for (int i = 0; i < bts.length; i++) {
            bts[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }

        return bts;
    }
    
    public String md5Enc(String msg) {
    	return encrypt(statickey(), msg);
    }
    
    public String md5Dec(String msg) {
    	return decrypt(statickey(), msg);
    }

}