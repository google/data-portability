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

package org.dataportabilityproject.transfer.smugmug.photos;

import static org.dataportabilityproject.transfer.smugmug.photos.SmugMugInterface.ALBUMS_KEY;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.http.HttpTransport;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.dataportabilityproject.spi.transfer.provider.ExportResult;
import org.dataportabilityproject.spi.transfer.provider.ExportResult.ResultType;
import org.dataportabilityproject.spi.transfer.provider.Exporter;
import org.dataportabilityproject.spi.transfer.types.ContinuationData;
import org.dataportabilityproject.spi.transfer.types.ExportInformation;
import org.dataportabilityproject.spi.transfer.types.IdOnlyContainerResource;
import org.dataportabilityproject.spi.transfer.types.StringPaginationToken;
import org.dataportabilityproject.transfer.smugmug.photos.model.SmugMugAlbum;
import org.dataportabilityproject.transfer.smugmug.photos.model.SmugMugAlbumImage;
import org.dataportabilityproject.transfer.smugmug.photos.model.SmugMugAlbumInfoResponse;
import org.dataportabilityproject.transfer.smugmug.photos.model.SmugMugAlbumsResponse;
import org.dataportabilityproject.transfer.smugmug.photos.model.SmugMugResponse;
import org.dataportabilityproject.transfer.smugmug.photos.model.SmugMugUserResponse;
import org.dataportabilityproject.types.transfer.auth.AppCredentials;
import org.dataportabilityproject.types.transfer.auth.TokenSecretAuthData;
import org.dataportabilityproject.types.transfer.models.photos.PhotoAlbum;
import org.dataportabilityproject.types.transfer.models.photos.PhotoModel;
import org.dataportabilityproject.types.transfer.models.photos.PhotosContainerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SmugMugPhotosExporter
    implements Exporter<TokenSecretAuthData, PhotosContainerResource> {

  static final String ALBUM_TOKEN_PREFIX = "album:";
  static final String PHOTO_TOKEN_PREFIX = "photo:";
  static final String ALBUM_URL_FORMATTER = "/api/v2/album/%s!images";

  private final AppCredentials appCredentials;
  private final HttpTransport transport;
  private final Logger logger = LoggerFactory.getLogger(SmugMugPhotosExporter.class);
  private final ObjectMapper mapper;

  private SmugMugInterface smugMugInterface;

  public SmugMugPhotosExporter(
      HttpTransport transport, AppCredentials appCredentials, ObjectMapper mapper) {
    this(null, transport, appCredentials, mapper);
  }

  @VisibleForTesting
  SmugMugPhotosExporter(
      SmugMugInterface smugMugInterface,
      HttpTransport transport,
      AppCredentials appCredentials,
      ObjectMapper mapper) {
    this.transport = transport;
    this.appCredentials = appCredentials;
    this.smugMugInterface = smugMugInterface;
    this.mapper = mapper;
  }

  @Override
  public ExportResult<PhotosContainerResource> export(UUID jobId, TokenSecretAuthData authData) {
    return export(jobId, authData, new ExportInformation(null, null));
  }

  @Override
  public ExportResult<PhotosContainerResource> export(
      UUID jobId, TokenSecretAuthData authData, ExportInformation exportInformation) {

    StringPaginationToken paginationToken =
        (StringPaginationToken) exportInformation.getPaginationData();
    IdOnlyContainerResource resource =
        (IdOnlyContainerResource) exportInformation.getContainerResource();

    if (resource != null) {
      return exportPhotos(resource, paginationToken, getOrCreateSmugMugInterface(authData));
    } else {
      return exportAlbums(paginationToken, getOrCreateSmugMugInterface(authData));
    }
  }

  private ExportResult<PhotosContainerResource> exportAlbums(
      StringPaginationToken paginationData, SmugMugInterface smugMugInterface) {

    SmugMugResponse<SmugMugAlbumsResponse> albumsResponse;
    try {
      // Make request to SmugMug
      String albumInfoUri;
      if (paginationData != null) {
        String token = paginationData.getToken();
        Preconditions.checkState(
            token.startsWith(ALBUM_TOKEN_PREFIX), "Invalid pagination token " + token);
        albumInfoUri = token.substring(ALBUM_TOKEN_PREFIX.length());
      } else {
        SmugMugResponse<SmugMugUserResponse> userResponse = smugMugInterface.makeUserRequest();
        albumInfoUri = userResponse.getResponse().getUser().getUris().get(ALBUMS_KEY).getUri();
      }
      albumsResponse = smugMugInterface.makeAlbumRequest(albumInfoUri);
    } catch (IOException e) {
      logger.warn("Unable to get AlbumsResponse: " + e.getMessage());
      return new ExportResult(ResultType.ERROR, e.getMessage());
    }

    // Set up continuation data
    StringPaginationToken paginationToken = null;
    if (albumsResponse.getResponse().getPageInfo() != null
        && albumsResponse.getResponse().getPageInfo().getNextPage() != null) {
      paginationToken =
          new StringPaginationToken(
              ALBUM_TOKEN_PREFIX + albumsResponse.getResponse().getPageInfo().getNextPage());
    }
    ContinuationData continuationData = new ContinuationData(paginationToken);

    // Build album list
    List<PhotoAlbum> albumsList = new ArrayList<>();
    for (SmugMugAlbum album : albumsResponse.getResponse().getAlbums()) {
      albumsList.add(new PhotoAlbum(album.getAlbumKey(), album.getTitle(), album.getDescription()));
      continuationData.addContainerResource(new IdOnlyContainerResource(album.getAlbumKey()));
    }
    PhotosContainerResource resource = new PhotosContainerResource(albumsList, null);

    // Get result type
    ResultType resultType = ResultType.CONTINUE;
    if (paginationToken == null) {
      resultType = ResultType.END;
    }

    return new ExportResult<>(resultType, resource, continuationData);
  }

  private ExportResult<PhotosContainerResource> exportPhotos(
      IdOnlyContainerResource containerResource,
      StringPaginationToken paginationData,
      SmugMugInterface smugMugInterface) {
    List<PhotoModel> photoList = new ArrayList<>();

    // Make request to SmugMug
    String photoInfoUri;
    if (paginationData != null) {
      String token = paginationData.getToken();
      Preconditions.checkState(
          token.startsWith(PHOTO_TOKEN_PREFIX), "Invalid pagination token " + token);
      photoInfoUri = token.substring(PHOTO_TOKEN_PREFIX.length());
    } else {
      String id = containerResource.getId();
      photoInfoUri = String.format(ALBUM_URL_FORMATTER, id);
    }

    SmugMugResponse<SmugMugAlbumInfoResponse> albumInfoResponse = null;
    try {
      albumInfoResponse = smugMugInterface.makeAlbumInfoRequest(photoInfoUri);
    } catch (IOException e) {
      logger.warn("Unable to get SmugMugAlbumInfo");
      return new ExportResult(ResultType.ERROR, e.getMessage());
    }

    // Set up continuation data
    StringPaginationToken pageToken = null;
    if (albumInfoResponse.getResponse().getPageInfo().getNextPage() != null) {
      pageToken =
          new StringPaginationToken(
              PHOTO_TOKEN_PREFIX + albumInfoResponse.getResponse().getPageInfo().getNextPage());
    }
    ContinuationData continuationData = new ContinuationData(pageToken);

    // Make list of photos
    for (SmugMugAlbumImage image : albumInfoResponse.getResponse().getImages()) {
      String title = image.getTitle();
      if (Strings.isNullOrEmpty(title)) {
        title = image.getFileName();
      }

      photoList.add(
          new PhotoModel(
              title,
              // TODO: sign the archived uri to get private photos to work.
              image.getArchivedUri(),
              image.getCaption(),
              getMimeType(image.getFormat()),
              containerResource.getId()));
    }
    PhotosContainerResource resource = new PhotosContainerResource(null, photoList);

    // Get result type
    ResultType resultType = ResultType.CONTINUE;
    if (pageToken == null) {
      resultType = ResultType.END;
    }

    return new ExportResult<>(resultType, resource, continuationData);
  }

  // Returns the provided interface, or a new one specific to the authData provided.
  private SmugMugInterface getOrCreateSmugMugInterface(TokenSecretAuthData authData) {
    return smugMugInterface == null
        ? new SmugMugInterface(transport, appCredentials, authData, mapper)
        : smugMugInterface;
  }

  private String getMimeType(String smugMugformat) {
    switch (smugMugformat) {
      case "JPG":
      case "JPEG":
        return "image/jpeg";
      case "PNG":
        return "image/png";
      default:
        throw new IllegalArgumentException("Don't know how to map: " + smugMugformat);
    }
  }
}
