// All rights reserved.
//
// This source code is licensed under the BSD-style license found in
// the LICENSE file in the root directory of this source tree. An
// additional grant of patent rights can be found in the PATENTS file
// in the same directory.
//

package com.facebook.fbadb.agent;

import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Build;
import android.os.Handler;
import android.os.Process;
import android.util.JsonWriter;

import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Agent {

  private static final String PROGNAME = "fb-adb-agent";
  private static final int QUERY_PROCESSES = (1<<0);
  private static final int QUERY_PACKAGES = (1<<1);
  private static final int GET_ACTIVITIES = (1<<2);

  private static final int USER_OWNER = 0;

  private static Object cachedPm = null;

  private static ActivityManager getAm() throws Exception {
    Constructor amConstructor = ActivityManager.class.getDeclaredConstructor(
        Context.class, Handler.class);
    amConstructor.setAccessible(true);
    // We can pass null here because ActivityManager doesn't actually use these values for the
    // specific methods we want to call, all of which just punt to IActivityManager.
    return (ActivityManager) amConstructor.newInstance(null, null);
  }

  private static void writeSingleAppProcessInfo(
      JsonWriter writer,
      ActivityManager.RunningAppProcessInfo info) throws Exception {
    writer.beginObject()
        .name("importance").value(info.importance)
        .name("importanceReasonCode").value(info.importanceReasonCode)
        .name("importanceReasonPid").value(info.importanceReasonPid)
        .name("lru").value(info.lru)
        .name("pid").value(info.pid)
        .name("processName").value(info.processName)
        .name("uid").value(info.uid)
        ;

    writer.name("pkgList");
    writeStringArray(writer, info.pkgList);

    writer.endObject();
  }

  private static void writeAppProcessInfo(JsonWriter writer, ActivityManager am)
      throws Exception {
    writer.beginArray();
    for (ActivityManager.RunningAppProcessInfo info : am.getRunningAppProcesses()) {
      writeSingleAppProcessInfo(writer, info);
    }
    writer.endArray();
  }

  private static void writeSingleServiceInfo(
      JsonWriter writer,
      ActivityManager.RunningServiceInfo info) throws Exception {
    writer.beginObject()
        .name("activeSince").value(info.activeSince)
        .name("clientCount").value(info.clientCount)
        .name("clientLabel").value(info.clientLabel)
        .name("clientPackage").value(info.clientPackage)
        .name("crashCount").value(info.crashCount)
        .name("flags").value(info.flags)
        .name("foreground").value(info.foreground)
        .name("lastActivityTime").value(info.lastActivityTime)
        .name("pid").value(info.pid)
        .name("process").value(info.process)
        .name("restarting").value(info.restarting)
        .name("service").value(info.service.flattenToString())
        .name("started").value(info.started)
        .name("uid").value(info.uid)
        .endObject();
  }

  private static void writeServiceProcessInfo(JsonWriter writer, ActivityManager am)
      throws Exception {
    writer.beginArray();
    for (ActivityManager.RunningServiceInfo info : am.getRunningServices(Integer.MAX_VALUE)) {
      writeSingleServiceInfo(writer, info);
    }
    writer.endArray();
  }

  private static void writeSingleErrorInfo(
      JsonWriter writer,
      ActivityManager.ProcessErrorStateInfo info)
      throws Exception {
    writer.beginObject()
        .name("condition").value(info.condition)
        .name("longMsg").value(info.longMsg)
        .name("pid").value(info.pid)
        .name("processName").value(info.processName)
        .name("shortMsg").value(info.shortMsg)
        .name("stackTrace").value(info.stackTrace)
        .name("tag").value(info.tag)
        .name("uid").value(info.uid)
        .endObject();
  }

  private static void writeErrorProcessInfo(JsonWriter writer, ActivityManager am)
      throws Exception {
    List<ActivityManager.ProcessErrorStateInfo> ei = am.getProcessesInErrorState();
    writer.beginArray();
    // Yes, the API is documented as returning null instead of an empty list.
    if (ei != null) {
      for (ActivityManager.ProcessErrorStateInfo info : ei) {
        writeSingleErrorInfo(writer, info);
      }
    }
    writer.endArray();
  }

  private static void processDump(JsonWriter writer) throws Exception {
    ActivityManager am = getAm();
    writer.setIndent("  ");
    writer.name("running_processes");
    writeAppProcessInfo(writer, am);
    writer.name("running_services");
    writeServiceProcessInfo(writer, am);
    writer.name("error_processes");
    writeErrorProcessInfo(writer, am);
  }

  private static Object getIPackageManager() throws Exception {
    if (cachedPm == null) {
      Method getService = Class.forName("android.os.ServiceManager")
          .getMethod("getService", String.class);
      cachedPm = Class.forName("android.content.pm.IPackageManager$Stub")
          .getMethod("asInterface", android.os.IBinder.class)
          .invoke(null, getService.invoke(null, "package"));
    }

    return cachedPm;
  }

  private static List<PackageInfo> getInstalledPackages(int flags)
      throws Exception {
    Class clsIPackageManager = Class.forName("android.content.pm.IPackageManager");

    try {
      Object packageListSlice;

      try {
        packageListSlice = clsIPackageManager
            .getMethod("getInstalledPackages", int.class, int.class)
            .invoke(getIPackageManager(), flags, USER_OWNER);
      } catch (NoSuchMethodException ex) {
        // Try old UID-less version.
        packageListSlice = clsIPackageManager
            .getMethod("getInstalledPackages", int.class)
            .invoke(getIPackageManager(), flags);
      }

      return (List<PackageInfo>) packageListSlice
          .getClass()
          .getMethod("getList")
          .invoke(packageListSlice);
    } catch (NoSuchMethodException ex) {
      // Try the old batched API.  Loop until we've added all slices to the list.  AOSP comments
      // indicate the paging mechanism exists to work around IPC size limits --- size limits
      // that disappeared in KitKat, when the above simpler API appeared?
      List<PackageInfo> list = new ArrayList<PackageInfo>();
      Object slice;
      PackageInfo lastItem = null;

      do {
        final String lastKey = lastItem != null ? lastItem.packageName : null;
        slice = clsIPackageManager
            .getMethod("getInstalledPackages", int.class, String.class)
            .invoke(getIPackageManager(), flags, lastKey);
        lastItem = (PackageInfo) slice
            .getClass()
            .getMethod("populateList", List.class, android.os.Parcelable.Creator.class)
            .invoke(slice, list, android.content.pm.PackageInfo.CREATOR);
      } while (slice.getClass().getMethod("isLastSlice").invoke(slice).equals(false));

      return list;
    }
  }

  private static void writeStringArray(JsonWriter writer, String strings[])
      throws Exception {
    if (strings == null) {
      writer.nullValue();
    } else {
      writer.beginArray();
      for (String s : strings) {
        writer.value(s);
      }
      writer.endArray();
    }
  }

  private static void writeApplicationInfo(JsonWriter writer, ApplicationInfo info)
      throws Exception {
    writer.beginObject()
        .name("backupAgentName").value(info.backupAgentName)
        .name("className").value(info.className)
        .name("dataDir").value(info.dataDir)
        .name("descriptionRes").value(info.descriptionRes)
        .name("enabled").value(info.enabled)
        .name("flags").value(info.flags)
        .name("manageSpaceActivityName").value(info.manageSpaceActivityName)
        .name("nativeLibraryDir").value(info.nativeLibraryDir)
        .name("permission").value(info.permission)
        .name("processName").value(info.processName)
        .name("publicSourceDir").value(info.publicSourceDir)
        .name("sourceDir").value(info.sourceDir)
        .name("targetSdkVersion").value(info.targetSdkVersion)
        .name("taskAffinity").value(info.taskAffinity)
        .name("theme").value(info.theme)
        .name("uid").value(info.uid)
        ;

    writer.name("sharedLibraryFiles");
    writeStringArray(writer, info.sharedLibraryFiles);

    writer.endObject();
  }

  private static void writeActivityInfo(JsonWriter writer, ActivityInfo acti)
      throws Exception {
    writer.beginObject()
        .name("flags").value(acti.flags)
        .name("permission").value(acti.permission)
        .name("launchMode").value(acti.launchMode)
        .name("targetActivity").value(acti.targetActivity)
        .name("taskAffinity").value(acti.taskAffinity)
        .name("enabled").value(acti.enabled)
        .name("exported").value(acti.exported)
        .name("processName").value(acti.processName)
        .name("name").value(acti.name)
        .endObject();
  }

  private static void writePackageInfo(JsonWriter writer, PackageInfo info, int flags)
      throws Exception {
    writer.beginObject()
        .name("firstInstallTime").value(info.firstInstallTime)
        .name("lastUpdateTime").value(info.lastUpdateTime)
        .name("packageName").value(info.packageName)
        .name("sharedUserId").value(info.sharedUserId)
        .name("sharedUserLabel").value(info.sharedUserLabel)
        .name("versionCode").value(info.versionCode)
        .name("versionName").value(info.versionName)
        ;

    writer.name("applicationInfo");
    writeApplicationInfo(writer, info.applicationInfo);

    if ((flags & GET_ACTIVITIES) != 0) {
      writer.name("activities");
      writer.beginArray();
      if (info.activities != null) {
        for (ActivityInfo acti : info.activities) {
          writeActivityInfo(writer, acti);
        }
      }
      writer.endArray();
    }

    writer.endObject();
  }

  private static void packageDump(JsonWriter writer, int flags) throws Exception {
    writer.name("packages");
    writer.beginArray();
    int pmFlags = 0;
    if ((flags & GET_ACTIVITIES) != 0) {
      pmFlags |= PackageManager.GET_ACTIVITIES;
    }

    for (PackageInfo info : getInstalledPackages(pmFlags)) {
      writePackageInfo(writer, info, flags);
    }

    writer.endArray();
  }

  private static List<ResolveInfo> queryIntentActivities(Intent intent, int flags)
      throws Exception {
    Class clsIPackageManager = Class.forName("android.content.pm.IPackageManager");
    Method queryIntentActivities = clsIPackageManager
        .getMethod(
            "queryIntentActivities",
            Intent.class,
            String.class,
            int.class,
            int.class);

    Object activities = queryIntentActivities
        .invoke(getIPackageManager(), intent, null, 0, USER_OWNER);
    if (activities == null) {
        return Collections.emptyList();
    } else if (!(activities instanceof List)) {
        Method getList = activities.getClass().getMethod("getList");
        activities = getList.invoke(activities);
    }

    return (List<ResolveInfo>) activities;
  }

  private static Intent getLaunchIntentForPackage(String packageName)
      throws Exception {
    Intent intentToResolve = new Intent(Intent.ACTION_MAIN);
    intentToResolve.addCategory(Intent.CATEGORY_INFO);
    intentToResolve.setPackage(packageName);
    List<ResolveInfo> ris = queryIntentActivities(intentToResolve, 0);
    if (ris == null || ris.size() <= 0) {
      intentToResolve.removeCategory(Intent.CATEGORY_INFO);
      intentToResolve.addCategory(Intent.CATEGORY_LAUNCHER);
      intentToResolve.setPackage(packageName);
      ris = queryIntentActivities(intentToResolve, 0);
    }
    if (ris == null || ris.size() <= 0) {
      return null;
    }
    Intent intent = new Intent(intentToResolve);
    intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    intent.setClassName(ris.get(0).activityInfo.packageName,
        ris.get(0).activityInfo.name);
    return intent;
  }

  /**
   * Like {@link PackageManager#getLaunchIntentForPackage()}, but prefer an activity explicitly
   * marked as a debug entry point to any of the standard activities.
   *
   * @param packageName Package name to query
   * @return Resolved intent or null
   */
  private static Intent getDebugStartIntent(String packageName) throws Exception {
    ActivityManager am = getAm();
    Intent intentToResolve = new Intent(Intent.ACTION_MAIN);
    intentToResolve.addCategory("com.facebook.intent.category.DEBUG_ENTRY_POINT");
    intentToResolve.setPackage(packageName);
    List<ResolveInfo> ris = queryIntentActivities(intentToResolve, 0);
    if (ris != null && !ris.isEmpty()) {
      Intent intent = new Intent(intentToResolve);
      intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
      intent.setClassName(
          ris.get(0).activityInfo.packageName,
          ris.get(0).activityInfo.name);
      return intent;
    }

    return getLaunchIntentForPackage(packageName);
  }

  private static void writeDebugLauncher(
      JsonWriter writer,
      String packageName) throws Exception {
    Intent intent = getDebugStartIntent(packageName);
    ComponentName resolved = intent == null ? null : intent.getComponent();
    writer
        .beginObject()
        .name("packageName").value(packageName)
        .name("debugIntent").value(
            resolved != null
            ? resolved.flattenToString()
            : null)
        .endObject();
  }

  private static void processFindDebugLauncherPackages(
      JsonWriter writer,
      List<String> packages) throws Exception {
    if (!packages.isEmpty()) {
      writer.name("debug-launcher");
      writer.beginArray();
      for (String packageName : packages) {
        writeDebugLauncher(writer, packageName);
      }
      writer.endArray();
    }
  }

  private static void usage() throws Exception {
    System.out.println(
        String.format(
            "%s THING...: write JSON-format system information", PROGNAME));
    System.out.println("Each THING is either \"process-dump\" or \"package-dump\"");
    System.out.println("");
    System.out.println(
        String.format(
            "%s help: this usage information", PROGNAME));
  }

  public static void doMain(String[] args) throws Exception {
    if (args.length < 1) {
      System.err.println(String.format("%s: run -h for help", PROGNAME));
      System.exit(1);
    }

    int flags = 0;

    String FIND_DEBUG_LAUNCHER_PREFIX = "find-debug-launcher:";
    ArrayList<String> findDebugLauncherPackages = new ArrayList<>();

    for (String arg : args) {
      if (arg.equals("-h") || arg.equals("--help") || arg.equals("help")) {
        usage();
      } else if (arg.startsWith(FIND_DEBUG_LAUNCHER_PREFIX)) {
        findDebugLauncherPackages.add(
            arg.substring(FIND_DEBUG_LAUNCHER_PREFIX.length()));
      } else if (arg.equals("process-dump")) {
        flags |= QUERY_PROCESSES;
      } else if (arg.equals("package-dump")) {
        flags |= QUERY_PACKAGES;
      } else if (arg.equals("get-activities")) {
        flags |= GET_ACTIVITIES;
      } else {
        System.err.println(String.format("%s: unknown command %s", PROGNAME, arg));
        System.exit(1);
      }
    }

    JsonWriter writer = new JsonWriter(
        new BufferedWriter(
            new OutputStreamWriter(
                System.out, "UTF-8")));

    writer.setIndent("  ");
    writer.beginObject();

    if ((flags & QUERY_PROCESSES) != 0) {
      processDump(writer);
    }

    if ((flags & QUERY_PACKAGES) != 0) {
      packageDump(writer, flags);
    }

    processFindDebugLauncherPackages(writer, findDebugLauncherPackages);

    writer.endObject();
    writer.flush();
  }

  public static void main(String[] args) {
    // Need to explicitly catch at top-level: if we allow the exception to propagate, the VM will
    // abort and print the exception only to logcat, not stderr, where we want it.
    try {
      doMain(args);
    } catch (Throwable ex) {
      ex.printStackTrace(System.err);
      System.exit(2);
    }
  }
}
