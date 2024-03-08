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
 * @author Cameron Harmon (harmoncc@jmu.edu)
 */
public class KeyPairGenerator {
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

    public void test () throws Exception {
        generateKeyPair ("harmoncc-public.bin", "harmoncc-private.bin");
    }

    public static void main(String[] args) {
	try {
        	KeyPairGenerator generator = new KeyPairGenerator();
        	generator.test();
	} catch (Exception ex) {
		ex.printStackTrace ();
	}
    }
}
