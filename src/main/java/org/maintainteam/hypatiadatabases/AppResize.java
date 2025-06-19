package org.maintainteam.hypatiadatabases;

import com.google.common.base.CharMatcher;
import com.google.common.base.Charsets;
import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.Arrays;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AppResize {
    private static BloomFilter<String> signaturesMD5;
    private static BloomFilter<String> signaturesSHA1;
    private static BloomFilter<String> signaturesSHA256;
    private static BloomFilter<String> domains;

    private static int amtLinesValid = 0;
    private static int amtLinesInvalid = 0;
    private static int amtSignaturesReadMD5 = 0;
    private static int amtSignaturesReadSHA1 = 0;
    private static int amtSignaturesReadSHA256 = 0;
    private static int amtSignaturesAddedMD5 = 0;
    private static int amtSignaturesAddedSHA1 = 0;
    private static int amtSignaturesAddedSHA256 = 0;
    private static int amtDomainsRead = 0;
    private static int amtDomainsAdded = 0;

    private static boolean extendedMode = false;
    public static final Set<String> arrExclusions = new HashSet<>();

    private static final Set<String> setMD5 = new HashSet<>();
    private static final Set<String> setSHA1 = new HashSet<>();
    private static final Set<String> setSHA256 = new HashSet<>();
    private static final Set<String> setDomains = new HashSet<>();

    public static void main(String[] args) {
        extendedMode = args[0].contains("-extended");

        System.out.println("Processing exclusions:");
        File[] exclusions = new File(args[0] + "../exclusions/").listFiles();
        Arrays.sort(exclusions);
        for (File exclusionDatabase : exclusions) {
            try (Scanner s = new Scanner(exclusionDatabase)) {
                while (s.hasNextLine()) {
                    String line = s.nextLine().trim().toLowerCase();
                    if (line.contains(":")) line = line.split(":")[0];
                    if (!line.startsWith("#") && isHexadecimal(line) && (line.length() == 32 || line.length() == 40 || line.length() == 64)) {
                        arrExclusions.add(line);
                    }
                }
                System.out.println("\t" + exclusionDatabase.getName());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        System.out.println("\tLoaded " + arrExclusions.size() + " excluded hashes");

        if (args.length == 2 && !extendedMode) {
            System.out.println("Processing domains:");
            File domainDatabase = new File(args[1]);
            if (domainDatabase.exists()) {
                try (Scanner s = new Scanner(domainDatabase)) {
                    while (s.hasNextLine()) {
                        String line = s.nextLine().trim().toLowerCase();
                        if (!line.startsWith("#") && !line.isEmpty()) {
                            setDomains.add(line);
                            amtDomainsAdded++;
                        }
                        amtDomainsRead++;
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        System.out.println("Processing signatures:");
        File[] databases = new File(args[0]).listFiles();
        File extras = new File(args[0] + "../extras/");
        if (extras.exists() && !extendedMode) {
            databases = Stream.concat(Arrays.stream(databases), Arrays.stream(extras.listFiles())).toArray(File[]::new);
        }
        Arrays.sort(databases);
        for (File databaseLocation : databases) {
            if (databaseLocation.isFile()) {
                System.out.println("\t" + databaseLocation.getName());
                try (BufferedReader reader = getBufferedReader(databaseLocation)) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        processLine(line.trim().toLowerCase(), databaseLocation.getName());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        createFinalBloomFilters();
        writeBloomFilters(args[0]);

        System.out.println("Lines read: valid: " + amtLinesValid + ", invalid: " + amtLinesInvalid);
        System.out.println("Added count: md5: " + amtSignaturesAddedMD5 + ", sha1: " + amtSignaturesAddedSHA1 + ", sha256: " + amtSignaturesAddedSHA256 + ", domains: " + amtDomainsAdded);
    }

    private static void createFinalBloomFilters() {
        signaturesMD5 = BloomFilter.create(Funnels.stringFunnel(Charsets.US_ASCII), Math.max(setMD5.size(), 1), 0.00001);
        for (String hash : setMD5) signaturesMD5.put(hash);

        signaturesSHA1 = BloomFilter.create(Funnels.stringFunnel(Charsets.US_ASCII), Math.max(setSHA1.size(), 1), 0.00001);
        for (String hash : setSHA1) signaturesSHA1.put(hash);

        signaturesSHA256 = BloomFilter.create(Funnels.stringFunnel(Charsets.US_ASCII), Math.max(setSHA256.size(), 1), 0.00001);
        for (String hash : setSHA256) signaturesSHA256.put(hash);

        domains = BloomFilter.create(Funnels.stringFunnel(Charsets.US_ASCII), Math.max(setDomains.size(), 1), 0.00001);
        for (String domain : setDomains) domains.put(domain);
    }

    private static void writeBloomFilters(String basePath) {
        try {
            signaturesMD5.writeTo(new FileOutputStream(new File(basePath, "hypatia-md5-bloom.bin")));
            signaturesSHA1.writeTo(new FileOutputStream(new File(basePath, "hypatia-sha1-bloom.bin")));
            signaturesSHA256.writeTo(new FileOutputStream(new File(basePath, "hypatia-sha256-bloom.bin")));
            domains.writeTo(new FileOutputStream(new File(basePath, "hypatia-domains-bloom.bin")));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static BufferedReader getBufferedReader(File file) throws IOException {
        if (file.getName().endsWith(".gz")) {
            return new BufferedReader(new InputStreamReader(new GZIPInputStream(new FileInputStream(file))));
        } else {
            return new BufferedReader(new FileReader(file));
        }
    }

    private static void processLine(String line, String fileName) {
        if (line.isEmpty() || line.startsWith("#")) return;

        String potentialHash = line;
        if (fileName.endsWith(".hdb") || fileName.endsWith(".hsb") || fileName.endsWith(".hdu") || fileName.endsWith(".hsu")) {
            String[] parts = line.split(":");
            if (parts.length > 0) potentialHash = parts[0];
        } else if (fileName.endsWith(".loki")) {
            String[] parts = line.split(";");
            if (parts.length > 0) potentialHash = parts[0];
        }

        addChecked(potentialHash.trim(), true);
    }

    private static void addChecked(String hash, boolean report) {
        if (hash.length() < 4 || !isHexadecimal(hash)) {
            amtLinesInvalid++;
            if (report) System.out.println("\t\tINVALID: " + hash);
            return;
        }

        if (arrExclusions.contains(hash)) return;

        switch (hash.length()) {
            case 32:
                setMD5.add(hash);
                amtSignaturesAddedMD5++;
                amtSignaturesReadMD5++;
                break;
            case 40:
                setSHA1.add(hash);
                amtSignaturesAddedSHA1++;
                amtSignaturesReadSHA1++;
                break;
            case 64:
                setSHA256.add(hash);
                amtSignaturesAddedSHA256++;
                amtSignaturesReadSHA256++;
                break;
            default:
                amtLinesInvalid++;
                if (report) System.out.println("\t\tINVALID LENGTH: " + hash);
                return;
        }
        amtLinesValid++;
    }

    private static final Pattern HEXADECIMAL_PATTERN = Pattern.compile("\\p{XDigit}+");

    private static boolean isHexadecimal(String input) {
        Matcher matcher = HEXADECIMAL_PATTERN.matcher(input);
        return matcher.matches();
    }
}
