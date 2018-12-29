/*
 * Copyright (c) 2005, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.jboss.sun.net.httpserver;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.com.sun.net.httpserver.Headers;

class UnmodifiableHeaders extends Headers {

        Headers map;

        UnmodifiableHeaders(Headers map) {
            this.map = map;
        }

        @Override
        public int size() {return map.size();}

        @Override
        public boolean isEmpty() {return map.isEmpty();}

        @Override
        public boolean containsKey(Object key) {
            return map.containsKey (key);
        }

        @Override
        public boolean containsValue(Object value) {
            return map.containsValue(value);
        }

        @Override
        public List<String> get(Object key) {
            return map.get(key);
        }

        @Override
        public String getFirst (String key) {
            return map.getFirst(key);
        }


        @Override
        public List<String> put(String key, List<String> value) {
            return map.put (key, value);
        }

        @Override
        public void add (String key, String value) {
            throw new UnsupportedOperationException ("unsupported operation");
        }

        @Override
        public void set (String key, String value) {
            throw new UnsupportedOperationException ("unsupported operation");
        }

        @Override
        public List<String> remove(Object key) {
            throw new UnsupportedOperationException ("unsupported operation");
        }

        @Override
        public void putAll(Map<? extends String,? extends List<String>> t)  {
            throw new UnsupportedOperationException ("unsupported operation");
        }

        @Override
        public void clear() {
            throw new UnsupportedOperationException ("unsupported operation");
        }

        @Override
        public Set<String> keySet() {
            return Collections.unmodifiableSet (map.keySet());
        }

        @Override
        public Collection<List<String>> values() {
            return Collections.unmodifiableCollection(map.values());
        }

        /* TODO check that contents of set are not modifable : security */

        @Override
        public Set<Map.Entry<String, List<String>>> entrySet() {
            return Collections.unmodifiableSet (map.entrySet());
        }

        @Override
        public boolean equals(Object o) {return map.equals(o);}

        @Override
        public int hashCode() {return map.hashCode();}
    }
