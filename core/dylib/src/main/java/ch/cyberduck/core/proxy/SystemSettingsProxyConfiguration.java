package ch.cyberduck.core.proxy;

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

import ch.cyberduck.binding.application.NSWorkspace;
import ch.cyberduck.binding.foundation.NSAppleScript;
import ch.cyberduck.binding.foundation.NSURL;
import ch.cyberduck.core.Factory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class SystemSettingsProxyConfiguration implements ProxyFinder.Configuration {
    private static final Logger log = LogManager.getLogger(SystemSettingsProxyConfiguration.class);

    @Override
    public void configure() {
        NSWorkspace.sharedWorkspace().openURL(NSURL.URLWithString("x-apple.systempreferences:com.apple.Network-Settings.extension"));
    }
}
