package org.payjoindevkit;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal JSON parser for reading bitcoind RPC responses in {@link BIP77IntegrationTest}. The
 * JDK has no built-in JSON parser and bitcoind's response shapes here are simple (objects,
 * arrays, strings, numbers, booleans, null) - this avoids adding a JSON library dependency for
 * what a couple hundred lines of straightforward recursive-descent parsing covers. Not a
 * general-purpose JSON library: no streaming, no configurable number types, not built for reuse
 * outside this test.
 */
final class JsonRpc {
    private JsonRpc() {
    }

    static Value parse(String json) {
        Parser parser = new Parser(json);
        Value value = parser.parseValue();
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw new IllegalArgumentException("Trailing content in JSON: " + json);
        }
        return value;
    }

    /** {@code result} field convenience for bitcoind's {@code call()} wrapper, when the result is a bare string. */
    static String stringResult(String json) {
        return parse(json).asString();
    }

    /** {@code result.<field>} convenience, when the result is a JSON object. */
    static String objectField(String json, String field) {
        return parse(json).get(field).asString();
    }

    /** A parsed JSON value: null, boolean, number (as double), string, array, or object. */
    static final class Value {
        private final Object raw;

        private Value(Object raw) {
            this.raw = raw;
        }

        boolean isNull() {
            return raw == null;
        }

        boolean asBoolean() {
            return (Boolean) raw;
        }

        double asDouble() {
            return (Double) raw;
        }

        String asString() {
            return (String) raw;
        }

        @SuppressWarnings("unchecked")
        List<Value> asArray() {
            return (List<Value>) raw;
        }

        boolean has(String field) {
            return asObject().containsKey(field);
        }

        Value get(String field) {
            Value value = asObject().get(field);
            if (value == null) {
                throw new IllegalArgumentException("Missing JSON field: " + field);
            }
            return value;
        }

        @SuppressWarnings("unchecked")
        private Map<String, Value> asObject() {
            return (Map<String, Value>) raw;
        }
    }

    private static final class Parser {
        private final String json;
        private int pos;

        Parser(String json) {
            this.json = json;
        }

        boolean atEnd() {
            return pos >= json.length();
        }

        void skipWhitespace() {
            while (pos < json.length() && Character.isWhitespace(json.charAt(pos))) {
                pos++;
            }
        }

        Value parseValue() {
            skipWhitespace();
            char c = json.charAt(pos);
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> new Value(parseString());
                case 't' -> parseLiteral("true", Boolean.TRUE);
                case 'f' -> parseLiteral("false", Boolean.FALSE);
                case 'n' -> parseLiteral("null", null);
                default -> parseNumber();
            };
        }

        private Value parseLiteral(String literal, Object value) {
            if (!json.startsWith(literal, pos)) {
                throw new IllegalArgumentException("Invalid JSON literal at " + pos + " in: " + json);
            }
            pos += literal.length();
            return new Value(value);
        }

        private Value parseObject() {
            expect('{');
            Map<String, Value> fields = new LinkedHashMap<>();
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return new Value(fields);
            }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                fields.put(key, parseValue());
                skipWhitespace();
                char next = json.charAt(pos++);
                if (next == '}') {
                    break;
                }
                if (next != ',') {
                    throw new IllegalArgumentException("Expected ',' or '}' at " + (pos - 1) + " in: " + json);
                }
            }
            return new Value(fields);
        }

        private Value parseArray() {
            expect('[');
            List<Value> items = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return new Value(items);
            }
            while (true) {
                items.add(parseValue());
                skipWhitespace();
                char next = json.charAt(pos++);
                if (next == ']') {
                    break;
                }
                if (next != ',') {
                    throw new IllegalArgumentException("Expected ',' or ']' at " + (pos - 1) + " in: " + json);
                }
            }
            return new Value(items);
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = json.charAt(pos++);
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    char escaped = json.charAt(pos++);
                    switch (escaped) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'n' -> sb.append('\n');
                        case 't' -> sb.append('\t');
                        case 'r' -> sb.append('\r');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'u' -> {
                            String hex = json.substring(pos, pos + 4);
                            pos += 4;
                            sb.append((char) Integer.parseInt(hex, 16));
                        }
                        default -> throw new IllegalArgumentException("Invalid escape \\" + escaped);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Value parseNumber() {
            int start = pos;
            while (pos < json.length() && "-+.0123456789eE".indexOf(json.charAt(pos)) >= 0) {
                pos++;
            }
            return new Value(Double.parseDouble(json.substring(start, pos)));
        }

        private char peek() {
            return json.charAt(pos);
        }

        private void expect(char c) {
            char actual = json.charAt(pos++);
            if (actual != c) {
                throw new IllegalArgumentException("Expected '" + c + "' at " + (pos - 1) + " in: " + json);
            }
        }
    }
}
