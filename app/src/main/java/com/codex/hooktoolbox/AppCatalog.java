package com.codex.hooktoolbox;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

final class AppCatalog {
    private AppCatalog() {}

    static JSONArray userApps(Context context) throws JSONException {
        PackageManager pm = context.getPackageManager();
        List<ApplicationInfo> apps = pm.getInstalledApplications(PackageManager.GET_META_DATA);
        List<JSONObject> result = new ArrayList<>();
        for (ApplicationInfo app : apps) {
            boolean system = (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (system) continue;
            JSONObject item = new JSONObject();
            item.put("packageName", app.packageName);
            item.put("label", String.valueOf(pm.getApplicationLabel(app)));
            item.put("uid", app.uid);
            result.add(item);
        }
        result.sort(Comparator.comparing(item -> item.optString("label") + "\u0000" + item.optString("packageName"),
                String.CASE_INSENSITIVE_ORDER));
        JSONArray array = new JSONArray();
        for (JSONObject item : result) array.put(item);
        return array;
    }
}
