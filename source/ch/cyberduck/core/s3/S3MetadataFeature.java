package ch.cyberduck.core.s3;

/*
 * Copyright (c) 2002-2014 David Kocher. All rights reserved.
 * http://cyberduck.io/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Bug fixes, suggestions and comments should be sent to:
 * feedback@cyberduck.io
 */

import ch.cyberduck.core.Path;
import ch.cyberduck.core.PathContainerService;
import ch.cyberduck.core.exception.BackgroundException;
import ch.cyberduck.core.features.Headers;

import org.apache.log4j.Logger;
import org.jets3t.service.ServiceException;
import org.jets3t.service.model.StorageObject;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


/**
 * @version $Id$
 */
public class S3MetadataFeature implements Headers {
    private static final Logger log = Logger.getLogger(S3MetadataFeature.class);

    private S3Session session;

    private PathContainerService containerService
            = new S3PathContainerService();

    public S3MetadataFeature(final S3Session session) {
        this.session = session;
    }

    @Override
    public Map<String, String> getMetadata(final Path file) throws BackgroundException {
        if(file.isFile() || file.isPlaceholder()) {
            return new S3AttributesFeature(session).find(file).getMetadata();
        }
        return Collections.emptyMap();
    }

    @Override
    public void setMetadata(final Path file, final Map<String, String> metadata) throws BackgroundException {
        if(file.isFile() || file.isPlaceholder()) {
            if(log.isDebugEnabled()) {
                log.debug(String.format("Write metadata %s for file %s", metadata, file));
            }
            try {
                // Make sure to copy existing attributes
                final StorageObject target = new S3AttributesFeature(session).details(file);
                target.replaceAllMetadata(new HashMap<String, Object>(metadata));
                // Apply non standard ACL
                final S3AccessControlListFeature acl = new S3AccessControlListFeature(session);
                target.setAcl(acl.convert(acl.getPermission(file)));
                target.setStorageClass(new S3StorageClassFeature(session).getClass(file));
                target.setServerSideEncryptionAlgorithm(new S3EncryptionFeature(session).getEncryption(file));
                session.getClient().updateObjectMetadata(containerService.getContainer(file).getName(), target);
            }
            catch(ServiceException e) {
                throw new ServiceExceptionMappingService().map("Failure to write attributes of {0}", e, file);
            }
        }
    }
}
