//
// Adapted from net.sf.ntru.demo.SimpleExample
// Check https://github.com/tbuktu/ntru
//

import java.io.*;

//
// Packages for NTRUEncrypt
//
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.NtruEncrypt;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.EncryptionPrivateKey;

/**
 * Example code to use Tim Buktu's NTRU implementation
 * @author Jane Doe (wangxx@jmu.edu)
 * @date 12/26/2019; revised on 12/26/2021. All rights reserved
 */
public class EncryptionOracleFromAlice {
    // NTRU public/private key pair
    private EncryptionKeyPair kp = null;

    // create an instance of NtruEncrypt with a standard parameter set
    // 	   APR2011_439_FAST: offers 128-bit security
    // NtruEncrypt ntru = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);
    //
    //     APR2011_743_FAST: offers 256-bit security
    //     For spring 2022, use this one
    NtruEncrypt ntru = new NtruEncrypt(EncryptionParameters.APR2011_743_FAST);

    public String convertToString (byte[] data, int startPos) {
	char[] _hexArray = {'0', '1', '2', '3', '4', '5','6', '7', '8',
			    '9', 'A', 'B', 'C', 'D', 'E', 'F'};

	StringBuffer sb = new StringBuffer();
	for (int i=startPos; i <data.length; i++) {
		sb.append("" + _hexArray[(data[i] >> 4) & 0x0f] + _hexArray[data[i] & 0x0f]);
	}

	return sb.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
	int len = s.length();
	byte[] data = new byte[len / 2];
	for (int i = 0; i < len; i += 2) {
		data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
	}

	return data;
    }

    public void generateKeyPair (String inPublicKeyFilename, String inPrivateKeyFilename) throws Exception {
        System.out.println("NTRU key pair generation starts ......");
        
        // create an encryption key pair
        kp = ntru.generateKeyPair();

	//
	// Save the public key to file inPublicKeyFilename
	//
	EncryptionPublicKey euk = kp.getPublic();
	byte[] ukBytes = euk.getEncoded();
	System.out.println ("\nByte length of ENCODED public key = " + ukBytes.length);
	FileOutputStream fos1 = new FileOutputStream (inPublicKeyFilename);
	fos1.write (ukBytes);
	fos1.close();
        System.out.println ("The public key bytes are " + convertToString (ukBytes, 0));

	EncryptionPrivateKey epk = kp.getPrivate();
	byte[] pkBytes = epk.getEncoded();
	System.out.println ("\nByte length of ENCODED private key = " + pkBytes.length);
	FileOutputStream fos2 = new FileOutputStream (inPrivateKeyFilename);
	fos2.write (pkBytes);
	fos2.close();
        System.out.println ("The private key bytes are " + convertToString (pkBytes, 0));
    }

    public byte[] encrypt (byte[] inPlaintextBytes) {
        System.out.println("\nBefore encryption......");

        // encrypt the message with the public key created above
        byte[] ciphertextBytes = ntru.encrypt(inPlaintextBytes, kp.getPublic());
        System.out.println ("\nThe ciphertext is " + convertToString (ciphertextBytes, 0));

        return ciphertextBytes;
    }

    public byte[] decrypt (byte[] inCiphertextBytes) {
        // decrypt the message with the private key created above
        byte[] recoveredCleartextBytes = ntru.decrypt (inCiphertextBytes, kp);
        System.out.println ("The RECOVERED cleartext (in bytes) is " + convertToString (recoveredCleartextBytes, 0));

        return recoveredCleartextBytes;
    }

    public void loadKeyPairFromFiles (String inPrivateKeyFilename, String inPublicKeyFilename) throws Exception {
        File file = new File (inPrivateKeyFilename);
	int size = (int) file.length();
	// System.out.println ("File size = " + size);
	FileInputStream fis = new FileInputStream (inPrivateKeyFilename);
	byte[] privateKeyBytes = new byte[size];
	fis.read (privateKeyBytes);
	fis.close ();

        File file2 = new File (inPublicKeyFilename);
	int size2 = (int) file2.length();
	// System.out.println ("File size = " + size2);
	FileInputStream fis2 = new FileInputStream (inPublicKeyFilename);
	byte[] publicKeyBytes = new byte[size2];
	fis2.read (publicKeyBytes);
	fis2.close ();

	EncryptionPrivateKey epk = new EncryptionPrivateKey (privateKeyBytes);
	EncryptionPublicKey euk = new EncryptionPublicKey (publicKeyBytes);
	kp = new EncryptionKeyPair (epk, euk);
    }

    public void test () throws Exception {
        String msg = "Our names are Luke and Cameron"; 
        System.out.println ("The plaintext (before encryption) is " + msg);

        generateKeyPair ("harmoncc-public.bin", "harmoncc-private.bin");

        byte[] ciphertextBytes = encrypt (msg.getBytes());
        byte[] recoveredCleartextBytes = decrypt (ciphertextBytes);
        System.out.println ("The recovered cleartext is " + new String(recoveredCleartextBytes));
    }

    public static void main(String[] args) {
	try {
        	EncryptionOracleFromAlice ntruExample = new EncryptionOracleFromAlice();
        	ntruExample.test();
	} catch (Exception ex) {
		ex.printStackTrace ();
	}
    }
}
