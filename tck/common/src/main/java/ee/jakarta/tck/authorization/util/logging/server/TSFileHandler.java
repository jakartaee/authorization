/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */

/**
 * $Id$
 *
 * @author Raja Perumal
 *         07/13/02
 */
package ee.jakarta.tck.authorization.util.logging.server;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.logging.ErrorManager;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

/**
 * Handler that writes the TCK log file, starting a new one when it is created.
 * <p>
 * It doesn't keep the file open: every record is appended by opening the file, writing and closing it
 * again. The handler can therefore be created and used while a native image (e.g. Quarkus) is built,
 * where Servlet listeners may already run, without an open file ending up in the image. It also creates
 * the directory of the log file if needed.
 */
public class TSFileHandler extends Handler {

    private final File file;
    private boolean closed;

    public TSFileHandler(File file) throws IOException {
        this.file = file;
        setLevel(Level.ALL);
        setEncoding(StandardCharsets.UTF_8.name());
        setFormatter(new TSXMLFormatter());

        File dir = file.getAbsoluteFile().getParentFile();
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("Failed to create directory for logs: " + dir);
        }

        // Start a new log file
        if (file.exists() && !file.delete()) {
            throw new IOException("Failed to delete the existing log file " + file);
        }

        write(getFormatter().getHead(this));
    }

    public File getFile() {
        return file;
    }

    @Override
    public synchronized void publish(LogRecord record) {
        if (closed || !isLoggable(record)) {
            return;
        }

        final String message;
        try {
            message = getFormatter().format(record);
        } catch (Exception e) {
            reportError(null, e, ErrorManager.FORMAT_FAILURE);
            return;
        }

        try {
            write(message);
        } catch (IOException e) {
            reportError(null, e, ErrorManager.WRITE_FAILURE);
        }
    }

    @Override
    public void flush() {
        // Every record is written and the file closed right away
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;

        try {
            write(getFormatter().getTail(this));
        } catch (IOException e) {
            reportError(null, e, ErrorManager.CLOSE_FAILURE);
        }
    }

    private void write(String text) throws IOException {
        try (OutputStream output = new FileOutputStream(file, true)) {
            output.write(text.getBytes(StandardCharsets.UTF_8));
        }
    }
}
