package com.codex.hooktoolbox;

import java.util.regex.Pattern;

final class Target {
    private static final Pattern PACKAGE = Pattern.compile("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z0-9_]+)+");

    private Target() {}

    static String requirePackage(String value) {
        String pkg = value == null ? "" : value.trim();
        if (!PACKAGE.matcher(pkg).matches() || pkg.length() > 190) {
            throw new IllegalArgumentException("包名格式无效");
        }
        return pkg;
    }
}
