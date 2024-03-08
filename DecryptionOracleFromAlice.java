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
public class DecryptionOracleFromAlice {
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

    public byte[] loadCipherTextFromFiles (String inCipherTextFilename) throws Exception {
        File file = new File (inCipherTextFilename);
        int size = (int) file.length();
        // System.out.println ("File size = " + size);
        FileInputStream fis = new FileInputStream (inCipherTextFilename);
        byte[] ciphertextBytes = new byte[size];
        fis.read (ciphertextBytes);
        fis.close ();
        return ciphertextBytes;
    }

    public byte[] decrypt (byte[] inCiphertextBytes) {
        // decrypt the message with the private key
        byte[] recoveredCleartextBytes = ntru.decrypt (inCiphertextBytes, kp);
        System.out.println ("The RECOVERED cleartext (in bytes) is " + convertToString (recoveredCleartextBytes, 0));

        return recoveredCleartextBytes;
    }

    public void test () throws Exception {
        loadKeyPairFromFiles ("harmoncc-private.bin", "harmoncc-public.bin");
        byte[] ciphertextBytes = loadCipherTextFromFiles("harmoncc-ciphertext.bin");
        byte[] recoveredCleartextBytes = decrypt (ciphertextBytes);
        System.out.println ("The recovered cleartext is " + new String(recoveredCleartextBytes));
    }

    public static void main(String[] args) {
        try {
                DecryptionOracleFromAlice ntru = new DecryptionOracleFromAlice();
                ntru.test();
        } catch (Exception ex) {
            ex.printStackTrace ();
        }
    }
}
