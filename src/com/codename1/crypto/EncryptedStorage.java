/*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package com.codename1.crypto;

import com.codename1.io.Log;
import com.codename1.io.Storage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * A Storage implementation that seamlessly encrypts it's contents based on a key. To setup this 
 * encryption use the Storage.install() method, notice that this only applies to storage and doesn't
 * apply to the database or FileSystemStorage!
 *
 * @author Shai Almog
 */
public class EncryptedStorage extends Storage{
    private PaddedBufferedBlockCipher encryptCipher;
    private PaddedBufferedBlockCipher decryptCipher;
 
    private byte[] key;
    
    @Override
    public InputStream createInputStream(String name) throws IOException {
        try {
            byte[] buf = new byte[16];              
            byte[] obuf = new byte[512];            
            InputStream in = super.createInputStream(name);        
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            int noBytesRead = 0; 
            int noBytesProcessed = 0;   

            while ((noBytesRead = in.read(buf)) >= 0) {
                    noBytesProcessed = decryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
                    out.write(obuf, 0, noBytesProcessed);
            }
            noBytesProcessed = decryptCipher.doFinal(obuf, 0);
            out.write(obuf, 0, noBytesProcessed);

            out.close();        

            return new ByteArrayInputStream(out.toByteArray());
        } catch(InvalidCipherTextException err) {
            throw new IOException(err.toString());
        }
    }

    @Override
    public OutputStream createOutputStream(String name) throws IOException {
        return new EncryptedOutputStream(super.createOutputStream(name));
    }
    
    /**
     * Use this method 
     */
    public static void install(String keyStr) {
        try {
            byte[] bytes = keyStr.getBytes("UTF-8");
            byte[] key = new byte[24];
            for(int iter = 0 ;iter < key.length ; iter++) {
                key[iter] = bytes[iter % bytes.length];
            }
            EncryptedStorage i = new EncryptedStorage();
            i.key = key;
            i.InitCiphers();
            Storage.setStorageInstance(i);
        } catch (UnsupportedEncodingException ex) {
            // moronic exception 
            Log.e(ex);
        }
    }

    private void InitCiphers(){
        encryptCipher = new PaddedBufferedBlockCipher(new AESEngine());
        encryptCipher.init(true, new KeyParameter(key));
        decryptCipher =  new PaddedBufferedBlockCipher(new AESEngine());
        decryptCipher.init(false, new KeyParameter(key));
    }
    
    class EncryptedOutputStream extends OutputStream {
        private final OutputStream underlying;
        private byte[] obuf = new byte[16536];            
 
        public EncryptedOutputStream(OutputStream underlying) {
            this.underlying = underlying;
        }
        
        @Override
        public void close() throws IOException {
            flush();
            underlying.close();
        }

        @Override
        public void flush() throws IOException {
            try {
                int size = encryptCipher.doFinal(obuf, 0);

                if(size > 0) {
                    underlying.write(obuf, 0, size);
                }
            } catch(InvalidCipherTextException err) {
                throw new IOException(err.toString());
            }
            underlying.flush();
        }

        @Override
        public void write(byte[] b) throws IOException {
            write(b, 0, b.length);
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[] { (byte)b });
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            int encLen = (len / 16 + 1) * 16;
            if(obuf.length < encLen) {
                obuf = new byte[encLen + 16];
            }
            int size = encryptCipher.processBytes(b, off, len, obuf, 0);
            underlying.write(obuf, 0, size);
        }
    }
}
