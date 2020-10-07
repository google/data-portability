package org.datatransferproject.datatransfer.backblaze.photos;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.UUID;
import org.datatransferproject.api.launcher.Monitor;
import org.datatransferproject.datatransfer.backblaze.common.BackblazeDataTransferClient;
import org.datatransferproject.datatransfer.backblaze.exception.BackblazeCredentialsException;
import org.datatransferproject.spi.cloud.storage.TemporaryPerJobDataStore;
import org.datatransferproject.spi.transfer.idempotentexecutor.IdempotentImportExecutor;
import org.datatransferproject.spi.transfer.provider.ImportResult;
import org.datatransferproject.spi.transfer.provider.Importer;
import org.datatransferproject.transfer.ImageStreamProvider;
import org.datatransferproject.types.common.models.photos.PhotoAlbum;
import org.datatransferproject.types.common.models.photos.PhotoModel;
import org.datatransferproject.types.common.models.photos.PhotosContainerResource;
import org.datatransferproject.types.transfer.auth.TokenSecretAuthData;

public class BackblazePhotosImporter
    implements Importer<TokenSecretAuthData, PhotosContainerResource> {

  private static final String PHOTO_TRANSFER_MAIN_FOLDER = "Photo Transfer";

  private final TemporaryPerJobDataStore jobStore;
  private final ImageStreamProvider imageStreamProvider = new ImageStreamProvider();
  private final Monitor monitor;
  private BackblazeDataTransferClient b2Client;

  public BackblazePhotosImporter(Monitor monitor, TemporaryPerJobDataStore jobStore) {
    this.monitor = monitor;
    this.jobStore = jobStore;
  }

  @Override
  public ImportResult importItem(
      UUID jobId,
      IdempotentImportExecutor idempotentExecutor,
      TokenSecretAuthData authData,
      PhotosContainerResource data)
      throws Exception {
    if (data == null) {
      // Nothing to do
      return ImportResult.OK;
    }

    b2Client = getOrCreateB2Client(monitor, authData);

    if (data.getAlbums() != null && data.getAlbums().size() > 0) {
      for (PhotoAlbum album : data.getAlbums()) {
        idempotentExecutor.executeAndSwallowIOExceptions(
            album.getId(),
            String.format("Caching album name for album '%s'", album.getId()),
            () -> album.getName());
      }
    }

    if (data.getPhotos() != null && data.getPhotos().size() > 0) {
      for (PhotoModel photo : data.getPhotos()) {
        idempotentExecutor.executeAndSwallowIOExceptions(
            photo.getDataId(),
            photo.getTitle(),
            () -> importSinglePhoto(idempotentExecutor, b2Client, jobId, photo));
      }
    }

    return ImportResult.OK;
  }

  private String importSinglePhoto(
      IdempotentImportExecutor idempotentExecutor,
      BackblazeDataTransferClient b2Client,
      UUID jobId,
      PhotoModel photo)
      throws IOException {
    String albumName = idempotentExecutor.getCachedValue(photo.getAlbumId());

    InputStream inputStream;
    if (photo.isInTempStore()) {
      inputStream = jobStore.getStream(jobId, photo.getFetchableUrl()).getStream();
    } else {
      HttpURLConnection conn = imageStreamProvider.getConnection(photo.getFetchableUrl());
      inputStream = conn.getInputStream();
    }

    return b2Client.uploadFile(
        String.format("%s/%s/%s.jpg", PHOTO_TRANSFER_MAIN_FOLDER, albumName, photo.getDataId()),
        jobStore.getTempFileFromInputStream(inputStream, photo.getDataId(), ".jpg"));
  }

  private BackblazeDataTransferClient getOrCreateB2Client(
      Monitor monitor, TokenSecretAuthData authData)
      throws BackblazeCredentialsException, IOException {
    if (b2Client == null) {
      b2Client = new BackblazeDataTransferClient(monitor);
      b2Client.init(authData.getToken(), authData.getSecret());
    }
    return b2Client;
  }
}