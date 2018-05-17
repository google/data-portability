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
package org.dataportabilityproject.transport.jettyrest.rest;

import org.dataportabilityproject.api.action.Action;
import org.dataportabilityproject.types.client.transfer.CreateTransfer;
import org.dataportabilityproject.types.client.transfer.GetTransfer;
import org.dataportabilityproject.types.client.transfer.StartTransfer;
import org.dataportabilityproject.types.client.transfer.Transfer;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/** */
@Consumes({MediaType.APPLICATION_JSON})
@Produces({MediaType.APPLICATION_JSON})
@Path("/transfer")
public class TransferController {
  private final Action<CreateTransfer, Transfer> createAction;
  private final Action<StartTransfer, Transfer> startAction;
  private final Action<GetTransfer, Transfer> getAction;

  public TransferController(
      Action<CreateTransfer, Transfer> createAction,
      Action<StartTransfer, Transfer> startAction,
      Action<GetTransfer, Transfer> getAction) {
    this.createAction = createAction;
    this.startAction = startAction;
    this.getAction = getAction;
  }

  @GET
  @Path("{id}")
  public Transfer find(@PathParam("id") String id) {
    return getAction.handle((new GetTransfer(id)));
  }

  @POST
  public Transfer transferServices(CreateTransfer request) {
    return createAction.handle(request);
  }

  @POST
  @Path("{id}/start")
  public Transfer startTransfer(StartTransfer request) {
    return startAction.handle(request);
  }
}
