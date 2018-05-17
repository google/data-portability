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
package org.dataportabilityproject.transport.jdk.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.inject.Inject;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.dataportabilityproject.api.action.transfer.GetTransferServicesAction;
import org.dataportabilityproject.types.client.transfer.GetTransferServices;
import org.dataportabilityproject.api.launcher.TypeManager;
import org.dataportabilityproject.transport.jdk.http.HandlerUtils.HttpMethods;
import org.dataportabilityproject.types.client.transfer.TransferServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static com.google.common.net.HttpHeaders.CONTENT_TYPE;

/** HttpHandler for the {@link GetTransferServicesAction}. */
final class ListServicesHandler implements HttpHandler {

  public static final String PATH = "/_/listServices";
  private static final Logger logger = LoggerFactory.getLogger(ListServicesHandler.class);
  private final GetTransferServicesAction transferServicesAction;
  private final ObjectMapper objectMapper;

  @Inject
  ListServicesHandler(GetTransferServicesAction transferServicesAction, TypeManager typeManager) {
    this.transferServicesAction = transferServicesAction;
    this.objectMapper = typeManager.getMapper();
  }

  /** Services the {@link GetTransferServicesAction} via the {@link HttpExchange}. */
  @Override
  public void handle(HttpExchange exchange) throws IOException {
    Preconditions.checkArgument(HandlerUtils.validateRequest(exchange, HttpMethods.GET, PATH));
    logger.debug("received request: {}", exchange.getRequestURI());

    String transferDataType = HandlerUtils.getRequestParams(exchange).get(JsonKeys.DATA_TYPE);
    Preconditions.checkArgument(!Strings.isNullOrEmpty(transferDataType), "Missing data type");

    try {
      GetTransferServices actionRequest = new GetTransferServices(transferDataType);
      TransferServices actionResponse = transferServicesAction.handle(actionRequest);

      // Set response as type json
      Headers headers = exchange.getResponseHeaders();
      headers.set(CONTENT_TYPE, "application/json; charset=" + StandardCharsets.UTF_8.name());

      // Send response
      exchange.sendResponseHeaders(200, 0);
      objectMapper.writeValue(exchange.getResponseBody(), actionResponse);
    } catch (Exception e) {
      logger.warn("Error during action", e);
      handleError(exchange, transferDataType);
    }
  }

  /** Handles error response. TODO: Determine whether to return user facing error message here. */
  public void handleError(HttpExchange exchange, String transferDataType) throws IOException {
    TransferServices response =
        new TransferServices(transferDataType, Collections.emptySet(), Collections.emptySet());
    // Mark the response as type Json and send
    exchange
        .getResponseHeaders()
        .set(CONTENT_TYPE, "application/json; charset=" + StandardCharsets.UTF_8.name());
    exchange.sendResponseHeaders(200, 0);
    objectMapper.writeValue(exchange.getResponseBody(), response);
  }
}
