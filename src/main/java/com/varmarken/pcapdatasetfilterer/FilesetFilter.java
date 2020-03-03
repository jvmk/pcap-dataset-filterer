package com.varmarken.pcapdatasetfilterer;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Given a source directory (i.e., a directory where all the pcap files of the original, unfiltered dataset resides) and
 * a destination directory, recursively identifies all pcap(ng) files in the source directory and translates their paths
 * respective to the destination directory (such that any file hierarchy below source directory can be preserved in
 * destination directory). A {@code BiPredicate<Path, BasicFileAttributes>} may be provided to alter the filtering
 * logic (e.g., if specific pcap files should be excluded from the filtered dataset).
 */
class FilesetFilter {

    private final Path mInputRoot;

    private final BiPredicate<Path, BasicFileAttributes> mFileFilter;

    public FilesetFilter(Path inputFilesetRoot) {
        this(
                inputFilesetRoot,
                (path, attributes) -> FileSystems.getDefault().getPathMatcher("glob:**.{pcap,pcapng}").matches(path)
        );
    }

    public FilesetFilter(Path inputFilesetRoot, BiPredicate<Path, BasicFileAttributes> fileFilter) {
        mInputRoot = inputFilesetRoot;
        mFileFilter = fileFilter;
    }

    public Map<Path, Path> getDestinationPaths(Path destinationDir) throws IOException {
        try (Stream<Path> srcPathsStream = Files.find(mInputRoot, Integer.MAX_VALUE, mFileFilter)) {
            // Build a source path to destination path dictionary (one entry per pcap file).
            return srcPathsStream.collect(Collectors.toMap(Function.identity(), (Path srcPath) -> {
                // Preserving directory structure in output fileset using java.nio.file.Path:
                // 1) Use inputRootDir.relativize(childOfInputRootDir) to get relative path
                // 2) Use outputRootDir.resolve(relativePathFrom1) to produce full output path for file.
                Path relativePathSegment = mInputRoot.relativize(srcPath);
                return destinationDir.resolve(relativePathSegment);
            }));
        }
    }

}
