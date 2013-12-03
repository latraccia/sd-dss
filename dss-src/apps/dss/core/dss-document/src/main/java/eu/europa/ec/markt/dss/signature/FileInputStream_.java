package eu.europa.ec.markt.dss.signature;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * Test class
 */
public final class FileInputStream_ extends FileInputStream {

    private static final Logger LOG = Logger.getLogger(FileInputStream_.class.getName());

    private boolean opened = false;
    static int nextId = 0;
    private final int openId = getNextId();
    String fileName;

    private static int getNextId() {

        return ++nextId;
    }

    public FileInputStream_(File file) throws FileNotFoundException {
        super(file);
        fileName = file.getName();
        opened = true;
        LOG.fine("--------> opened [" + fileName + "] : " + openId);
    }

    @Override
    public void close() throws IOException {

        if (opened) {

            super.close();
            opened = false;
            LOG.fine("--------> closed [" + fileName + "] : " + openId);
        } else {

            LOG.fine("--------> already closed [" + fileName + "] : " + openId);
        }
    }

    @Override
    protected void finalize() throws IOException {

        if (opened) {

            LOG.fine("--------> FileInputStream not closed!!! [" + fileName + "] : " + openId);
        } else {

            LOG.fine("--------> FileInputStream was closed [" + fileName + "] : " + openId);
        }
        super.finalize();
    }
}
