/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.engine.function;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;

public class TStringList {

    String folderFileName;

    File file = null;

    String separator = "=";

    public int count = 0;

    private int locateBeginIndex = -1;
    private int locateEndIndex = -2;

    private int copyBeginIndex = -1;
    private int copyEndIndex = -2;

    Vector<String> strings = new Vector<String>();

    public TStringList() {

    }

    /**
     * @param folderFileName
     */
    public TStringList(final String folderFileName) {

        super();

        this.folderFileName = folderFileName;
        file = DSSUtils.getFile(folderFileName);
    }

    public TStringList clone() {

        try {
            super.clone();
        } catch (CloneNotSupportedException e) {
            throw new DSSException(e);
        }
        TStringList list = new TStringList();
        list.folderFileName = folderFileName;
        list.file = file;
        list.separator = separator;
        list.count = count;
        list.strings = (Vector<String>) strings.clone();
        return list;
    }

    public void append(final String lString) {

        strings.add(lString);
        count++;
    }

    public void clear() {

        strings.clear();
    }

    public boolean fileExists() {

        return file != null && file.exists();
    }

    public String getFileName() {

        return file.getName();
    }

    public String getFolderName() {

        return file.getPath();
    }

    public Vector<String> getLines() {

        return strings;
    }

    public String getLine(int index) {

        return strings.elementAt(index);
    }

    public void insert(final int index, final String string) {

        strings.insertElementAt(string, index);
        count++;
    }

    public String key(final int index) {

        final String string = strings.elementAt(index);
        int pos = string.indexOf(separator);
        return string.substring(0, pos);
    }

    public void load() {

        BufferedReader br = null;
        try {

            InputStream ips = new FileInputStream(file);
            InputStreamReader ipsr = new InputStreamReader(ips);
            br = new BufferedReader(ipsr);
            String line;
            while ((line = br.readLine()) != null) {

                strings.add(line);
            }
            count = strings.size();
            resetLocate();
        } catch (Exception e) {

            throw new DSSException(e);
        } finally {

            DSSUtils.closeQuietly(br);
        }
    }

    public void save(final String folderFileName) {

        this.folderFileName = folderFileName;
        file = DSSUtils.getFile(folderFileName);
        save();
    }

    public void save() {

        BufferedWriter br = null;
        try {

            OutputStream ips = new FileOutputStream(file);
            OutputStreamWriter ipsr = new OutputStreamWriter(ips);
            br = new BufferedWriter(ipsr);
            for (String line : strings) {

                br.write(line + "\r\n");
            }
        } catch (Exception e) {

            throw new DSSException(e);
        } finally {

            DSSUtils.closeQuietly(br);
        }
    }

    public void setLines(String lLines) {

        String _Token;
        int _Size = lLines.length();
        for (int _Idx = 0, _Pos = 0; _Pos < _Size; ) {

            _Pos = lLines.indexOf('\n', _Idx);
            if (_Pos == -1) {

                _Pos = _Size;
            }
            _Token = lLines.substring(_Idx, _Pos);
            int _LastPos = _Token.lastIndexOf('\r');
            if (_LastPos != -1) {

                _Token = _Token.substring(0, _LastPos);
            }
            strings.add(_Token);
            _Idx = _Pos + 1;
        }
        count = strings.size();
    }

    public void replace(String target, String replacement) {

        for (int ii = locateBeginIndex; ii <= locateEndIndex; ii++) {

            String string = strings.get(ii);
            if (string.contains(target)) {

                strings.set(ii, string.replace(target, replacement));
            }
        }
    }

    public void replaceFirst(String target, String replacement) {

        String string = strings.get(locateBeginIndex);
        if (string.contains(target)) {

            strings.set(locateBeginIndex, string.replace(target, replacement));
        }
    }

    public String value(final int lIdx) {

        final String _String = strings.elementAt(lIdx);
        int _Pos = _String.indexOf(separator);
        int _Len = _String.length();
        return _String.substring(_Pos, _Len - _Pos - 1);
    }

    public String valueOf(final String lKey) {

        for (int _ii = 0; _ii < strings.size(); _ii++) {

            if (key(_ii).equals(lKey)) {

                return value(_ii);
            }
        }
        return "";
    }

    public void resetLocate() {

        locateBeginIndex = 0;
        locateEndIndex = strings.size() - 1;
    }

    public void locate(String tag) {

        String locateBeginTag = "<" + tag + ">";
        String locateEndTag = "</" + tag + ">";
        int length = strings.size();
        boolean located = false;
        for (int ii = 0; ii < length; ii++) {

            String string = strings.get(ii).trim();
            if (!located && string.startsWith(locateBeginTag)) {

                located = true;
                locateBeginIndex = ii + 1;
            } else if (located && string.contains(locateEndTag)) {

                locateEndIndex = ii;
                break;
            }
        }
    }

    public void subLocate(String tag) {

        String locateBeginTag = "<" + tag + ">";
        String locateEndTag = "</" + tag + ">";
        int locateBeginIndex_ = locateBeginIndex;
        boolean located = false;
        for (int ii = locateBeginIndex; ii <= locateEndIndex; ii++) {

            String string = strings.get(ii).trim();
            if (!located && string.startsWith(locateBeginTag)) {

                located = true;
                locateBeginIndex_ = ii + 1;
            }
            if (located && string.contains(locateEndTag)) {

                locateEndIndex = ii;
                break;
            }
        }
        locateBeginIndex = locateBeginIndex_;
    }

    public void locate(String tag, String attr) {

        resetLocate();
        String locateBeginTag = "<" + tag;
        String locateEndTag = "</" + tag + ">";
        int length = strings.size();
        boolean located = false;
        for (int ii = 0; ii < length; ii++) {

            String string = strings.get(ii).trim();
            if (!located && string.startsWith(locateBeginTag)) {

                if (string.contains(attr)) {

                    located = true;
                    locateBeginIndex = ii;
                }
            } else if (located && string.contains(locateEndTag)) {

                locateEndIndex = ii;
                break;
            }
        }
    }

    public void locateLine(String tag, String attr) {

        String locateBeginTag = "<" + tag;
        int length = strings.size();
        for (int ii = 0; ii < length; ii++) {

            String string = strings.get(ii).trim();
            if (string.startsWith(locateBeginTag)) {

                if (string.contains(attr)) {

                    locateBeginIndex = ii;
                    locateEndIndex = ii;
                    break;
                }
            }
        }
    }

    public void keep(String tag, String attr) {

        String locateBeginTag = "<" + tag;
        String locateEndTag = "</" + tag + ">";
        boolean located = false;
        boolean toDelete = false;
        for (int ii = locateBeginIndex; ii < locateEndIndex; ii++) {

            String string = strings.get(ii).trim();
            if (!located && string.startsWith(locateBeginTag)) {

                located = true;
                if (!string.contains(attr)) {

                    toDelete = true;
                } else {

                    toDelete = false;
                }
            }
            if (located) {

                if (string.contains(locateEndTag)) {

                    located = false;
                    if (toDelete) {

                        toDelete = false;
                        strings.set(ii, "__TO_BE_DELETED__");
                    }
                } else if (toDelete) {

                    strings.set(ii, "__TO_BE_DELETED__");
                }
            }
        }
        removeMarkedLines();
    }

    /**
     *
     */
    private void removeMarkedLines() {
        int deletedCount = 0;
        for (int ii = locateEndIndex; ii >= locateBeginIndex; ii--) {

            String string = strings.get(ii);
            if (string.equals("__TO_BE_DELETED__")) {

                deletedCount++;
                strings.remove(ii);
            }
        }
        locateEndIndex -= deletedCount;
    }

    public void remove(String tag) {

        String locateBeginTag = "<" + tag;
        String locateEndTag = "</" + tag + ">";
        boolean located = false;
        boolean toDelete = false;
        for (int ii = locateBeginIndex; ii < locateEndIndex; ii++) {

            String string = strings.get(ii).trim();
            if (string.contains(locateBeginTag)) {

                located = true;
                toDelete = true;
            }
            if (located) {

                if (string.contains(locateEndTag)) {

                    located = false;
                    if (toDelete) {

                        toDelete = false;
                        strings.set(ii, "__TO_BE_DELETED__");
                    }
                } else if (toDelete) {

                    strings.set(ii, "__TO_BE_DELETED__");
                }
            }
        }
        removeMarkedLines();
    }

    public void insert(final String tag, final String value) {

        strings.insertElementAt("<" + tag + ">" + value + "</" + tag + ">", locateBeginIndex);
        count++;
    }

    public void copy() {

        copyBeginIndex = locateBeginIndex;
        copyEndIndex = locateEndIndex;
    }

    public void paste() {

        List<String> stringToCopy = new ArrayList<String>();
        for (int ii = copyEndIndex; ii >= copyBeginIndex; ii--) {

            stringToCopy.add(strings.elementAt(ii));
        }
        for (String string : stringToCopy) {

            strings.insertElementAt(string, locateBeginIndex);
            count++;
        }
    }
}
