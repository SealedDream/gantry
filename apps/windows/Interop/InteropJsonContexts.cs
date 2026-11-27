using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

// Source-generated JSON for interop calls that the trimmer flagged (IL2026). Each context carries the same options
// as the reflection-based JsonSerializerOptions it replaces, so the JSON on the wire is unchanged.

/// <summary>Activity log: camelCase, nulls left out (was ActivityClient.Json).</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ActivityFilter))]
[JsonSerializable(typeof(List<ActivitySessionDto>))]
[JsonSerializable(typeof(ActivityClient.SessionStart))]
[JsonSerializable(typeof(ActivityClient.SessionEnd))]
internal sealed partial class ActivityJsonContext : JsonSerializerContext;

/// <summary>Activity export: the shown rows as column → cell, indented.</summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(List<Dictionary<string, string>>))]
internal sealed partial class ActivityExportJsonContext : JsonSerializerContext;

/// <summary>Plain string lists (default options).</summary>
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(IReadOnlyList<string>))]
internal sealed partial class StringListJsonContext : JsonSerializerContext;

/// <summary>Custom properties: case-insensitive names (was LibraryClient.Json).</summary>
[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(List<CustomPropertyRow>))]
internal sealed partial class CustomPropertyJsonContext : JsonSerializerContext;

/// <summary>Library overview: camelCase (was OverviewNative's Json).</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(List<OverviewRowDto>))]
internal sealed partial class OverviewJsonContext : JsonSerializerContext;

/// <summary>Task hooks (B5): camelCase, as the C ABI writes and reads them.</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(List<TaskHookDto>))]
[JsonSerializable(typeof(List<ResolvedHookDto>))]
internal sealed partial class TaskHookJsonContext : JsonSerializerContext;

/// <summary>KeePass import (B8): case-insensitive names.</summary>
[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(KeePassPreviewDto))]
[JsonSerializable(typeof(KeePassImportResult))]
internal sealed partial class KeePassJsonContext : JsonSerializerContext;
