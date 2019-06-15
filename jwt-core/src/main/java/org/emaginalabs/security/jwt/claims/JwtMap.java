package org.emaginalabs.security.jwt.claims;

import org.springframework.util.Assert;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Class extend {@link Map} to store claims for token JWT
 *
 * @author Arquitectura
 * @since 1.0
 */
public class JwtMap implements Map<String, Object> {

    private final Map<String, Object> map;

    public JwtMap() {
        this.map = new LinkedHashMap<>();
    }

    public JwtMap(Map<String, Object> map) {
        this();
        Assert.notNull(map, "Map argument cannot be null.");
        putAll(map);
    }

    protected String getString(String name) {
        Object v = get(name);
        return v != null ? String.valueOf(v) : null;
    }


    protected void setValue(String name, Object v) {
        if (v == null) {
            map.remove(name);
        } else {
            map.put(name, v);
        }
    }


    @Override
    public int size() {
        return map.size();
    }

    @Override
    public boolean isEmpty() {
        return map.isEmpty();
    }

    @Override
    public boolean containsKey(Object o) {
        return map.containsKey(o);
    }

    @Override
    public boolean containsValue(Object o) {
        return map.containsValue(o);
    }

    @Override
    public Object get(Object o) {
        return map.get(o);
    }

    @Override
    public Object put(String s, Object o) {
        if (o == null) {
            return map.remove(s);
        } else {
            return map.put(s, o);
        }
    }

    @Override
    public Object remove(Object o) {
        return map.remove(o);
    }

    @SuppressWarnings("NullableProblems")
    @Override
    public void putAll(Map<? extends String, ?> m) {
        if (m == null) {
            return;
        }
        for (String s : m.keySet()) {
            put(s, m.get(s));
        }
    }

    @Override
    public void clear() {
        map.clear();
    }

    @Override
    public Set<String> keySet() {
        return map.keySet();
    }

    @Override
    public Collection<Object> values() {
        return map.values();
    }

    @Override
    public Set<Entry<String, Object>> entrySet() {
        return map.entrySet();
    }

    @Override
    public String toString() {
        return map.toString();
    }

    @Override
    public int hashCode() {
        return map.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return map.equals(obj);
    }
}
