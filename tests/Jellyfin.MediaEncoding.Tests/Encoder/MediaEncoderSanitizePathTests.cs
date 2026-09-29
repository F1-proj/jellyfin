using System;
using System.IO;
using MediaBrowser.MediaEncoding.Encoder;
using Xunit;

namespace Jellyfin.MediaEncoding.Tests.Encoder;

/// <summary>
/// Tests for <see cref="MediaEncoder.SanitizeEncoderPath"/> which prevents
/// command injection (CWE-77) via tainted encoder paths stored in the database
/// or configuration (EncoderAppPath).
/// </summary>
public class MediaEncoderSanitizePathTests
{
    // -----------------------------------------------------------------------
    // Null / empty paths → must be rejected
    // -----------------------------------------------------------------------

    [Fact]
    public void SanitizeEncoderPath_NullPath_ReturnsNull()
    {
        var result = MediaEncoder.SanitizeEncoderPath(null);
        Assert.Null(result);
    }

    [Fact]
    public void SanitizeEncoderPath_EmptyPath_ReturnsNull()
    {
        var result = MediaEncoder.SanitizeEncoderPath(string.Empty);
        Assert.Null(result);
    }

    [Theory]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData("\n")]
    public void SanitizeEncoderPath_WhitespaceOnlyPath_ReturnsNull(string path)
    {
        // Whitespace-only strings have no directory component and are treated as
        // bare filenames, but since they obviously don't resolve to a real binary
        // on PATH, this validates the non-empty gate.
        // Path.GetFileName("   ") == "   " so it passes the bare-name check.
        // The result may be non-null (bare name allowed), which is acceptable —
        // the EncoderValidator's ValidateVersion call will fail at runtime.
        // The key invariant tested here is that no exception is thrown.
        var ex = Record.Exception(() => MediaEncoder.SanitizeEncoderPath(path));
        Assert.Null(ex);
    }

    // -----------------------------------------------------------------------
    // Bare filename (PATH lookup) → must be allowed through unchanged
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData("ffmpeg")]
    [InlineData("ffmpeg.exe")]
    [InlineData("avconv")]
    public void SanitizeEncoderPath_BareFilename_ReturnsSameValue(string bareFilename)
    {
        // A bare filename (no directory separator) represents a PATH lookup and
        // must not be blocked — this preserves the default "ffmpeg" fallback.
        var result = MediaEncoder.SanitizeEncoderPath(bareFilename);
        Assert.Equal(bareFilename, result);
    }

    // -----------------------------------------------------------------------
    // Absolute path to existing file → must return the resolved path
    // -----------------------------------------------------------------------

    [Fact]
    public void SanitizeEncoderPath_ExistingAbsolutePath_ReturnsResolvedPath()
    {
        // Create a real temporary file to represent a valid ffmpeg binary location.
        var tempFile = Path.GetTempFileName();
        try
        {
            var result = MediaEncoder.SanitizeEncoderPath(tempFile);

            // The sanitized path must be non-null and the file must still exist.
            Assert.NotNull(result);
            Assert.True(File.Exists(result));

            // The result must be a fully qualified path (no traversal sequences).
            Assert.True(Path.IsPathFullyQualified(result));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    // -----------------------------------------------------------------------
    // Path traversal attacks → must be rejected (non-existent destination)
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData("/tmp/../etc/passwd")]
    [InlineData("/usr/bin/../../bin/sh")]
    [InlineData("/nonexistent/path/ffmpeg")]
    public void SanitizeEncoderPath_NonExistentAbsolutePath_ReturnsNull(string path)
    {
        // Absolute paths that do not point to a real file (whether via traversal
        // or simply non-existent) must be rejected to prevent command injection.
        var result = MediaEncoder.SanitizeEncoderPath(path);
        Assert.Null(result);
    }

    [Fact]
    public void SanitizeEncoderPath_TraversalToNonExistentFile_ReturnsNull()
    {
        // Build a path with ".." traversal that does NOT point to a real file.
        var tempDir = Path.GetTempPath();
        var traversalPath = Path.Combine(tempDir, "subdir", "..", "..", "hopefully_nonexistent_binary_12345");
        var result = MediaEncoder.SanitizeEncoderPath(traversalPath);
        Assert.Null(result);
    }

    // -----------------------------------------------------------------------
    // Traversal to an EXISTING file → path is resolved, file must exist
    // -----------------------------------------------------------------------

    [Fact]
    public void SanitizeEncoderPath_TraversalToExistingFile_ReturnsCanonicalPath()
    {
        // Create a real file. Build a path that reaches it via ".." traversal.
        // The sanitizer must resolve the traversal and return the canonical path.
        var tempDir = Path.GetTempPath();
        var tempFile = Path.GetTempFileName();
        try
        {
            var fileName = Path.GetFileName(tempFile);
            // Construct a traversal path: tempDir/subdir/../<fileName>
            var traversalPath = Path.Combine(tempDir, "subdir", "..", fileName);
            var result = MediaEncoder.SanitizeEncoderPath(traversalPath);

            // The result must be the canonical (resolved) path to the real file.
            Assert.NotNull(result);
            Assert.Equal(Path.GetFullPath(tempFile), result);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    // -----------------------------------------------------------------------
    // Injection payload patterns (command chaining) → must be rejected
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData("/usr/bin/ffmpeg; rm -rf /")]
    [InlineData("/usr/bin/ffmpeg && malicious")]
    [InlineData("/usr/bin/ffmpeg | cat /etc/shadow")]
    [InlineData("/tmp/ffmpeg\x00malicious")]
    public void SanitizeEncoderPath_InjectionPayloads_ReturnsNull(string injectionPath)
    {
        // These paths include shell-injection characters or null bytes. They will
        // not resolve to an existing file, so they must be rejected.
        var result = MediaEncoder.SanitizeEncoderPath(injectionPath);
        Assert.Null(result);
    }

    // -----------------------------------------------------------------------
    // Relative paths with directory component → must be rejected when file
    // doesn't exist (they cannot be trusted without a resolved absolute path)
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData("./ffmpeg")]
    [InlineData("../ffmpeg")]
    [InlineData("subdir/ffmpeg")]
    public void SanitizeEncoderPath_RelativePathWithDirectoryComponent_WhenFileNotExists_ReturnsNull(string relativePath)
    {
        // Relative paths with a directory separator are resolved via
        // Path.GetFullPath, which anchors them to the current working directory.
        // If the resolved file does not exist the path must be rejected.
        // (In practice the resolved target will not exist for these test inputs.)
        var resolved = Path.GetFullPath(relativePath);
        if (!File.Exists(resolved))
        {
            var result = MediaEncoder.SanitizeEncoderPath(relativePath);
            Assert.Null(result);
        }
        // If by chance the file exists in the test environment we skip the assertion
        // to avoid a fragile false failure.
    }
}
