package ch.cyberduck.core;

/*
 *  Copyright (c) 2005 David Kocher. All rights reserved.
 *  http://cyberduck.ch/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  Bug fixes, suggestions and comments should be sent to:
 *  dkocher@cyberduck.ch
 */

import ch.cyberduck.core.i18n.Locale;
import ch.cyberduck.core.io.FileWatcher;
import ch.cyberduck.core.io.FileWatcherListener;
import ch.cyberduck.core.io.RepeatableFileInputStream;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

import java.io.*;
import java.net.MalformedURLException;

/**
 * @version $Id$
 */
public class Local extends AbstractPath implements Attributes {
    private static Logger log = Logger.getLogger(Local.class);

    public Permission getPermission() {
        return null;
    }

    public void setPermission(Permission p) {
        ;
    }

    public boolean isVolume() {
        return null == _impl.getParent();
    }

    public boolean isDirectory() {
        return _impl.isDirectory();
    }

    public boolean isFile() {
        return _impl.isFile();
    }

    /**
     * Checks whether a given file is a symbolic link.
     * <p/>
     * <p>It doesn't really test for symbolic links but whether the
     * canonical and absolute paths of the file are identical - this
     * may lead to false positives on some platforms.</p>
     *
     * @return true if the file is a symbolic link.
     */
    public boolean isSymbolicLink() {
        if(!Local.this.exists()) {
            return false;
        }
        // For a link that actually points to something (either a file or a directory),
        // the absolute path is the path through the link, whereas the canonical path
        // is the path the link references.
        try {
            return !_impl.getAbsolutePath().equals(_impl.getCanonicalPath());
        }
        catch(IOException e) {
            return false;
        }
    }

    public void setType(int i) {
        ;
    }

    public void setSize(long size) {
        ;
    }

    public void setOwner(String owner) {
        ;
    }

    public void setGroup(String group) {
        ;
    }

    public String getOwner() {
        return null;
    }

    public String getGroup() {
        return null;
    }

    public long getModificationDate() {
        return _impl.lastModified();
    }

    public void setModificationDate(long millis) {
        ;
    }

    public long getCreationDate() {
        return this.getModificationDate();
    }

    public void setCreationDate(long millis) {
        ;
    }

    public long getAccessedDate() {
        return this.getModificationDate();
    }

    public void setAccessedDate(long millis) {
        ;
    }

    public int getType() {
        final int t = this.isFile() ? AbstractPath.FILE_TYPE : AbstractPath.DIRECTORY_TYPE;
        if(this.isSymbolicLink()) {
            return t | AbstractPath.SYMBOLIC_LINK_TYPE;
        }
        return t;
    }

    public long getSize() {
        if(this.isDirectory()) {
            return 0;
        }
        return _impl.length();
    }

    protected File _impl;

    public Local(Local parent, String name) {
        this(parent.getAbsolute(), name);
    }

    public Local(String parent, String name) {
        if(!Path.DELIMITER.equals(name)) {
            name = name.replace('/', ':');
        }
        // See trac #933
        this.setPath(parent, name);
    }

    public Local(String path) {
        this.setPath(path);
    }

    public Local(File path) {
        this.setPath(path.getAbsolutePath());
    }

    /**
     *
     */
    protected void init() {
        attributes = this;
    }

    /**
     * @param listener
     */
    public void watch(FileWatcherListener listener) throws IOException {
        FileWatcher.instance().watch(this, listener);
    }

    public boolean isReadable() {
        return _impl.canRead();
    }

    public boolean isWritable() {
        return _impl.canWrite();
    }

    /**
     * Creates a new file and sets its resource fork to feature a custom progress icon
     *
     * @return
     */
    public boolean touch() {
        if(!this.exists()) {
            try {
                if(_impl.createNewFile()) {
                    this.setIcon(0);
                }
            }
            catch(IOException e) {
                log.error(e.getMessage());
            }
        }
        return false;
    }

    /**
     * @param progress An integer from -1 and 9. If -1 is passed, the icon should be removed.
     */
    public void setIcon(int progress) {
        log.warn("No implementation available");
    }

    public void delete() {
        this.delete(true);
    }

    public void delete(boolean trash) {
        if(trash) {
            this.trash();
        }
        else {
            _impl.delete();
        }
    }

    /**
     * Move file to trash.
     */
    public void trash() {
        log.warn("No implementation available");
    }

    /**
     * @return Always return false
     */
    @Override
    public boolean isCached() {
        return false;
    }

    private Cache<Local> cache;

    public Cache<Local> cache() {
        if(null == cache) {
            cache = new Cache<Local>();
        }
        return this.cache;
    }

    public AttributedList<Local> list() {
        final AttributedList<Local> childs = new AttributedList<Local>();
        File[] files = _impl.listFiles();
        if(null == files) {
            log.error("_impl.listFiles == null");
            return childs;
        }
        for(File file : files) {
            childs.add(LocalFactory.createLocal(file));
        }
        return childs;
    }

    /**
     * @return the file type for the extension of this file provided by launch services
     */
    public String kind() {
        if(this.attributes.isDirectory()) {
            return Locale.localizedString("Folder");
        }
        final String extension = this.getExtension();
        if(StringUtils.isEmpty(extension)) {
            return Locale.localizedString("Unknown");
        }
        // Native file type mapping
        final String kind = this.kind(this.getExtension());
        if(StringUtils.isEmpty(kind)) {
            return Locale.localizedString("Unknown");
        }
        return kind;
    }

    /**
     * @param extension
     * @return
     */
    protected String kind(String extension) {
        return null;
    }

    public String getAbsolute() {
        return _impl.getAbsolutePath();
    }

    public String getAbbreviatedPath() {
        return this.getAbsolute();
    }

    public <T> PathReference<T> getReference() {
        return null;
    }

    @Override
    public String getSymbolicLinkPath() {
        try {
            return _impl.getCanonicalPath();
        }
        catch(IOException e) {
            log.error(e.getMessage());
            return this.getAbsolute();
        }
    }

    public String getName() {
        return _impl.getName();
    }

    public AbstractPath getParent() {
        return LocalFactory.createLocal(_impl.getParentFile());
    }

    public boolean exists() {
        return _impl.exists();
    }

    public void setPath(String name) {
        _impl = new File(Path.normalize(name));
        this.init();
    }

    public void mkdir(boolean recursive) {
        if(recursive) {
            _impl.mkdirs();
        }
        else {
            _impl.mkdir();
        }
    }

    @Override
    public void writePermissions(Permission perm, boolean recursive) {
        log.warn("No implementation available");
    }

    public void rename(AbstractPath renamed) {
        _impl.renameTo(new File(this.getParent().getAbsolute(), renamed.getAbsolute()));
        this.setPath(this.getParent().getAbsolute(), renamed.getAbsolute());
    }

    public void copy(AbstractPath copy) {
        if(copy.equals(this)) {
            return;
        }
        FileInputStream in = null;
        FileOutputStream out = null;
        try {
            in = new FileInputStream(_impl);
            out = new FileOutputStream(copy.getAbsolute());
            IOUtils.copy(in, out);
        }
        catch(IOException e) {
            log.error(e.getMessage());
        }
        finally {
            IOUtils.closeQuietly(in);
            IOUtils.closeQuietly(out);
        }
    }

    @Override
    public int hashCode() {
        return _impl.getAbsolutePath().hashCode();
    }

    @Override
    public boolean equals(Object other) {
        if(null == other) {
            return false;
        }
        if(other instanceof Local) {
            return this.getAbsolute().equalsIgnoreCase(((AbstractPath) other).getAbsolute());
        }
        return false;
    }

    @Override
    public String toString() {
        return this.getAbsolute();
    }

    public String toURL() {
        try {
            return _impl.toURI().toURL().toString();
        }
        catch(MalformedURLException e) {
            log.error(e.getMessage());
            return null;
        }
    }

    /**
     * The default application for this file as set by the launch services
     *
     * @return Full path to the application bundle. Null if unknown
     */
    public String getDefaultEditor() {
        final String extension = this.getExtension();
        if(StringUtils.isEmpty(extension)) {
            return null;
        }
        return this.applicationForExtension(extension);
    }

    protected String applicationForExtension(String extension) {
        log.warn("No implementation available");
        return null;
    }

    /**
     * Not implemented
     *
     * @param originUrl
     * @param dataUrl
     */
    public void setQuarantine(final String originUrl, final String dataUrl) {
        log.warn("No implementation available");
    }

    /**
     * Not implemented
     *
     * @param dataUrl
     */
    public void setWhereFrom(final String dataUrl) {
        log.warn("No implementation available");
    }

    public static class OutputStream extends FileOutputStream {
        public OutputStream(Local local, boolean resume) throws FileNotFoundException {
            super(local._impl, resume);
        }
    }

    public static class InputStream extends RepeatableFileInputStream {
        public InputStream(Local local) throws FileNotFoundException {
            super(local._impl);
        }
    }
}