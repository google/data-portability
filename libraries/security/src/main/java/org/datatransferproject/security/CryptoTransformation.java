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

/** Provides compile-time constants for secure crypto transformations. For use 
in creation of Encrypter/Decrypter */
public enum CryptoTransformation {
	AES_CBC_NOPADDING,
	RSA_ECB_PKCS1,
	AES_CBC_PKCS5PADDING
}

