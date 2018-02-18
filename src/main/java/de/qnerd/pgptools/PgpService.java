package de.qnerd.pgptools;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.springframework.stereotype.Service;

@Service
public class PgpService {

	public void encrypt(String keyfile, String datafile) throws IOException, PGPException, NoSuchProviderException {
		PGPPublicKey readPublicKey = readPublicKey(keyfile);
		File outFile = new File(datafile+".pgp");
		FileOutputStream fos = new FileOutputStream(outFile);
		encryptFile(fos, datafile, readPublicKey, false, true);
		fos.close();
		
	}
	
	public void encryptFile(OutputStream out, String fileName,
			PGPPublicKey encKey, boolean armor, boolean withIntegrityCheck)
					throws IOException, NoSuchProviderException, PGPException
	{
		Security.addProvider(new BouncyCastleProvider());

		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
				PGPCompressedData.ZIP);

		org.bouncycastle.openpgp.PGPUtil.writeFileToLiteralData(comData.open(bOut),
				PGPLiteralData.BINARY, new File(fileName));

		comData.close();

		JcePGPDataEncryptorBuilder c = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC");

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);

		JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());

		cPk.addMethod(d);

		byte[] bytes = bOut.toByteArray();

		OutputStream cOut = cPk.open(out, bytes.length);

		cOut.write(bytes);

		cOut.close();

		out.close();
	}
	
	 private PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException
	    {
	        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
	        PGPPublicKey pubKey = readPublicKey(keyIn);
	        keyIn.close();
	        return pubKey;
	}
	 
	 
	 /**
	     * A simple routine that opens a key ring file and loads the first available key
	     * suitable for encryption.
	     * 
	     * @param input data stream containing the public key data
	     * @return the first public key found.
	     * @throws IOException
	     * @throws PGPException
	     */
	    private PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException
	    {
	        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
	            PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

	        //
	        // we just loop through the collection till we find a key suitable for encryption, in the real
	        // world you would probably want to be a bit smarter about this.
	        //

	        Iterator keyRingIter = pgpPub.getKeyRings();
	        while (keyRingIter.hasNext())
	        {
	            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

	            Iterator keyIter = keyRing.getPublicKeys();
	            while (keyIter.hasNext())
	            {
	                PGPPublicKey key = (PGPPublicKey)keyIter.next();

	                if (key.isEncryptionKey())
	                {
	                    return key;
	                }
	            }
	        }

	        throw new IllegalArgumentException("Can't find encryption key in key ring.");
	    }
	    
	    
	    private PGPSecretKey readSecretKey(String fileName) throws IOException, PGPException
	    {
	        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
	        PGPSecretKey secKey = readSecretKey(keyIn);
	        keyIn.close();
	        return secKey;
	    }

	    /**
	     * A simple routine that opens a key ring file and loads the first available key
	     * suitable for signature generation.
	     * 
	     * @param input stream to read the secret key ring collection from.
	     * @return a secret key.
	     * @throws IOException on a problem with using the input stream.
	     * @throws PGPException if there is an issue parsing the input stream.
	     */
	    private PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException
	    {
	        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
	            PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

	        //
	        // we just loop through the collection till we find a key suitable for encryption, in the real
	        // world you would probably want to be a bit smarter about this.
	        //

	        Iterator keyRingIter = pgpSec.getKeyRings();
	        while (keyRingIter.hasNext())
	        {
	            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();

	            Iterator keyIter = keyRing.getSecretKeys();
	            while (keyIter.hasNext())
	            {
	                PGPSecretKey key = (PGPSecretKey)keyIter.next();

	                if (key.isSigningKey())
	                {
	                    return key;
	                }
	            }
	        }

	        throw new IllegalArgumentException("Can't find signing key in key ring.");
	}


}
