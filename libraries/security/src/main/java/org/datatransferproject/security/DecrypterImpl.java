/*
 * Copyright 2018 The Data Transfer Project Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.datatransferproject.security;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.io.BaseEncoding;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import org.datatransferproject.api.launcher.Monitor;

/**
 * Provides AES and RSA-based encryption implementations for decryption. See {@link
 * DecrypterFactory} to create.
 */
final class DecrypterImpl implements Decrypter {
  private final Key key;
  private final CryptoTransformation transformation;
  private final Monitor monitor;

  DecrypterImpl(CryptoTransformation transformation, Key key, Monitor monitor) {
    this.key = key;
    this.transformation = transformation;
    this.monitor = monitor;
  }

  @Override
  public String decrypt(String encrypted) {
    try {
      byte[] decoded = BaseEncoding.base64Url().decode(encrypted);
      Cipher cipher;
      switch (transformation) {
        case AES_CBC_NOPADDING:
          cipher = Cipher.getInstance("AES/CBC/NoPadding");
          cipher.init(Cipher.DECRYPT_MODE, key, generateIv(cipher));
          break;
        case AES_CBC_PKCS5PADDING:
          cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
          cipher.init(Cipher.DECRYPT_MODE, key, generateIv(cipher));
          break;
        case RSA_ECB_PKCS1:
          cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
          cipher.init(Cipher.DECRYPT_MODE, key);
          break;
        default:
          throw new AssertionError("How could this happen...");
      }
      byte[] decrypted = cipher.doFinal(decoded);
      if (decrypted == null || decrypted.length <= cipher.getBlockSize()) {
        throw new RuntimeException("incorrect decrypted text.");
      }
      byte[] data = new byte[decrypted.length - cipher.getBlockSize()];
      System.arraycopy(decrypted, cipher.getBlockSize(), data, 0, data.length);
      return new String(data, UTF_8);
    } catch (BadPaddingException
        | IllegalBlockSizeException
        | InvalidAlgorithmParameterException
        | InvalidKeyException
        | NoSuchAlgorithmException
        | NoSuchPaddingException e) {
      monitor.severe(() -> format("Error decrypting data, length: %s", encrypted.length()), e);
      throw new RuntimeException(e);
    }
  }

  private static final IvParameterSpec generateIv(Cipher cipher) throws NoSuchAlgorithmException {
    SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
    byte[] iv = new byte[cipher.getBlockSize()];
    randomSecureRandom.nextBytes(iv);
    return new IvParameterSpec(iv);
  }
}