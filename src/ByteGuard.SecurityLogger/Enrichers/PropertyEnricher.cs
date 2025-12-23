namespace ByteGuard.SecurityLogger.Enrichers;

internal static class PropertiesEnricher
{
    /// <summary>
    /// Populate the properties from the given metadata instance.
    /// </summary>
    /// <param name="properties">Properties to populate.</param>
    /// <param name="metadata">Metadata instance.</param>
    internal static void PopulatePropertiesFromMetadata(Dictionary<string, object?> properties, SecurityEventMetadata? metadata)
    {
        if (metadata is null) return;

        if (!string.IsNullOrWhiteSpace(metadata.UserAgent))
            properties.Add("UserAgent", metadata.UserAgent);

        if (!string.IsNullOrWhiteSpace(metadata.SourceIp))
            properties.Add("SourceIp", metadata.SourceIp);

        if (!string.IsNullOrWhiteSpace(metadata.HostIp))
            properties.Add("HostIp", metadata.HostIp);

        if (!string.IsNullOrWhiteSpace(metadata.Hostname))
            properties.Add("Hostname", metadata.Hostname);

        if (!string.IsNullOrWhiteSpace(metadata.Protocol))
            properties.Add("Protocol", metadata.Protocol);

        if (!string.IsNullOrWhiteSpace(metadata.Port))
            properties.Add("Port", metadata.Port);

        if (!string.IsNullOrWhiteSpace(metadata.RequestUri))
            properties.Add("RequestUri", metadata.RequestUri);

        if (!string.IsNullOrWhiteSpace(metadata.RequestMethod))
            properties.Add("RequestMethod", metadata.RequestMethod);

        if (!string.IsNullOrWhiteSpace(metadata.Region))
            properties.Add("Region", metadata.Region);

        if (!string.IsNullOrWhiteSpace(metadata.Geo))
            properties.Add("Geo", metadata.Geo);
    }
}
