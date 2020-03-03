package com.varmarken.pcapdatasetfilterer;

import com.varmarken.pcaptrimmer.PcapTrimmer;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.namednumber.DataLinkType;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

public class Main {

    public static void main(String[] args) throws IOException, PcapNativeException, NotOpenException {
        Path originalDatasetRoot = Paths.get(args[0]);
        Path destinationRoot = Paths.get(args[1]);
        FilesetFilter filesets = new FilesetFilter(originalDatasetRoot);
        // Determine what pcap files to keep, and determine their filepaths.
        Map<Path, Path> fileMappings = filesets.getDestinationPaths(destinationRoot);
        for (Map.Entry<Path, Path> e : fileMappings.entrySet()) {
            Path srcPath = e.getKey();
            Path dstPath = e.getValue();
            System.out.println("Source: " + srcPath.toString());
            System.out.println("Target: " + dstPath.toString());
            // We assume that dst (and src) are files, not dirs.
            if (Files.isDirectory(dstPath)) {
                System.out.println("[WARNING] '" + dstPath.toString() + " is a directory. Expected a file. Skipping.");
                continue;
            }
            // Create missing output folders as necessary.
            Files.createDirectories(dstPath.getParent());
            // Now filter the pcap.
            PcapTrimmer pcapTrimmer = new PcapTrimmer(srcPath.toFile(), dstPath.toFile(), new LocalIpTrafficFilter());
            // No link layer encapsulation in the files we need to process.
            pcapTrimmer.setDataLinkType(DataLinkType.RAW);
            pcapTrimmer.trimPcap();
        }
    }

}
