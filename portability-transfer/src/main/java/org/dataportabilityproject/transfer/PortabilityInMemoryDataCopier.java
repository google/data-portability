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
package org.dataportabilityproject.transfer;

import com.google.common.collect.ImmutableList;
import com.google.inject.Provider;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import javax.inject.Inject;
import org.dataportabilityproject.spi.transfer.provider.ExportResult;
import org.dataportabilityproject.spi.transfer.provider.ExportResult.ResultType;
import org.dataportabilityproject.spi.transfer.provider.Exporter;
import org.dataportabilityproject.spi.transfer.provider.ImportResult;
import org.dataportabilityproject.spi.transfer.provider.Importer;
import org.dataportabilityproject.spi.transfer.types.ContinuationData;
import org.dataportabilityproject.spi.transfer.types.ExportInformation;
import org.dataportabilityproject.types.transfer.auth.AuthData;
import org.dataportabilityproject.types.transfer.models.ContainerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link InMemoryDataCopier}.
 */
final class PortabilityInMemoryDataCopier implements InMemoryDataCopier {

  private static final AtomicInteger COPY_ITERATION_COUNTER = new AtomicInteger();
  private static final Logger logger = LoggerFactory.getLogger(PortabilityInMemoryDataCopier.class);

  private static final List<String> fatalRegexes = ImmutableList.of("*fatal*");

  /**
   * Lazy evaluate exporter and importer as their providers depend on the polled {@code
   * PortabilityJob} which is not available at startup.
   */
  private final Provider<Exporter> exporter;

  private final Provider<Importer> importer;

  @Inject
  public PortabilityInMemoryDataCopier(Provider<Exporter> exporter, Provider<Importer> importer) {
    this.exporter = exporter;
    this.importer = importer;
  }

  /**
   * Kicks off transfer job {@code jobId} from {@code exporter} to {@code importer}.
   */
  @Override
  public void copy(AuthData exportAuthData, AuthData importAuthData, UUID jobId)
      throws IOException {
    // Initial copy, starts off the process with no previous paginationData or containerResource
    // information
    Optional<ExportInformation> emptyExportInfo = Optional.empty();
    copyHelper(jobId, exportAuthData, importAuthData, emptyExportInfo);
  }

  /**
   * Transfers data from the given {@code exporter} optionally starting at the point specified in
   * the provided {@code exportInformation}. Imports the data using the provided {@code importer}.
   * If there is more data to required to be exported, recursively copies using the specific {@link
   * ExportInformation} to continue the process.
   *
   * @param exportAuthData The auth data for the export
   * @param importAuthData The auth data for the import
   * @param exportInformation Any pagination or resource information to use for subsequent calls.
   */
  private void copyHelper(
      UUID jobId,
      AuthData exportAuthData,
      AuthData importAuthData,
      Optional<ExportInformation> exportInformation)
      throws IOException {

    logger.debug("copy iteration: {}", COPY_ITERATION_COUNTER.incrementAndGet());

    // NOTE: order is important below, do the import of all the items, then do continuation
    // then do sub resources, this ensures all parents are populated before children get
    // processed.
    ExportResult<?> exportResult = runExportLogic(jobId, exportAuthData, exportInformation);

    if (exportResult.getType().equals(ResultType.ERROR)) {
      logger.warn("Error happened during export: {}", exportResult.getMessage());
      return;
    }

    logger.debug("Starting import");
    ImportResult importResult = importer.get()
        .importItem(jobId, importAuthData, exportResult.getExportedData());
    logger.debug("Finished import");
    if (importResult.getType().equals(ImportResult.ResultType.ERROR)) {
      logger.warn("Error happened during import: {}", importResult.getMessage());
      return;
    }

    // Import and Export were successful, determine what to do next
    ContinuationData continuationData = (ContinuationData) exportResult.getContinuationData();

    if (null != continuationData) {
      // Process the next page of items for the resource
      if (null != continuationData.getPaginationData()) {
        logger.debug("starting off a new copy iteration with pagination info");
        copyHelper(
            jobId,
            exportAuthData,
            importAuthData,
            Optional.of(new ExportInformation(
                continuationData.getPaginationData(),
                exportInformation.get().getContainerResource())));
      }

      // Start processing sub-resources
      if (continuationData.getContainerResources() != null
          && !continuationData.getContainerResources().isEmpty()) {
        for (ContainerResource resource : continuationData.getContainerResources()) {
          copyHelper(jobId, exportAuthData, importAuthData,
              Optional.of(new ExportInformation(null, resource)));
        }
      }
    }
  }

  private ExportResult runExportLogic(UUID jobId, AuthData exportAuthData,
      Optional<ExportInformation> exportInformation) {
    ExportResult<?> exportResult = exportHelper(jobId, exportAuthData, exportInformation);
    if (exportResult.getType() == ResultType.ERROR) {
      ExceptionResponse response = checkRetry(exportResult.getMessage());
      if (response.canRetry) {
        int attempts = 1;
        // TODO: what if different kinds of errors have different max retries, and we start with one
        // kind of error and then start seeing another?
        while (attempts < response.maxRetries && response.canRetry) {
          exportResult = exportHelper(jobId, exportAuthData, exportInformation);
          if (exportResult.getType() != ResultType.ERROR) {
            return exportResult;
          } else {
            attempts += 1;
            response = checkRetry(exportResult.getMessage());
          }
        }
      }
    }
    return exportResult;
  }

  private ExportResult exportHelper(UUID jobId, AuthData exportAuthData,
      Optional<ExportInformation> exportInformation) {
    logger.debug("Starting export");
    ExportResult<?> exportResult = exporter.get().export(jobId, exportAuthData, exportInformation);
    logger.debug("Finishing export");
    return exportResult;
  }

  private ExceptionResponse checkRetry(String exceptionMessage) {
    for (String fatalRegex : fatalRegexes) {
      if (exceptionMessage.matches(fatalRegex)) {
        return new ExceptionResponse(false, 0);
      }
    }
    return new ExceptionResponse(true, 5);
  }

  private class ExceptionResponse {
    private boolean canRetry;
    private int maxRetries;

    private ExceptionResponse(boolean canRetry, int maxRetries) {
      this.canRetry = canRetry;
      this.maxRetries = maxRetries;
    }
  }

}
