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

import com.google.common.base.Preconditions;
import org.datatransferproject.api.launcher.Monitor;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Methods for creating {@link Decrypter} classes for given types of encryption keys and algorithms.
 */
public class DecrypterFactory {
  private Monitor monitor;

  public DecrypterFactory(Monitor monitor) {
    this.monitor = monitor;
  }

  /**
   * Creates a {@link DecrypterImpl} with the given {@link SecretKey} for use with "AES"-based
   * symmetric encryption.
   */
  public Decrypter create(SecretKey key) {
    Preconditions.checkArgument(key.getAlgorithm().equals("AES"));
    return new DecrypterImpl(CryptoTransformation.AES_CBC_PKCS5PADDING, key, monitor);
  }

  /**
   * Creates a {@link DecrypterImpl} with the given {@link PublicKey} for use with "RSA"-based
   * asymmetric encryption.
   */
  public Decrypter create(PublicKey key) {
    Preconditions.checkArgument(key.getAlgorithm().equals("RSA"));
    return new DecrypterImpl(CryptoTransformation.RSA_ECB_PKCS1, key, monitor);
  }

  /**
   * Creates a {@link DecrypterImpl} with the given {@link PrivateKey} for use with "RSA"-based
   * asymmetric encryption.
   */
  public Decrypter create(PrivateKey key) {
    Preconditions.checkArgument(key.getAlgorithm().equals("RSA"));
    return new DecrypterImpl(CryptoTransformation.RSA_ECB_PKCS1, key, monitor);
  }
}
