namespace ByteGuard.SecurityLogger;

/// <summary>
/// Metadata associated with a security event.
/// </summary>
public record SecurityEventMetadata
{
    /// <summary>
    /// User agent of the caller.
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// IP-address of the caller.
    /// </summary>
    public string? SourceIp { get; set; }

    /// <summary>
    /// IP-address of the host.
    /// </summary>
    public string? HostIp { get; set; }

    /// <summary>
    /// Hostname of the host.
    /// </summary>
    public string? Hostname { get; set; }

    /// <summary>
    /// Protocol used for the request.
    /// </summary>
    public string? Protocol { get; set; }

    /// <summary>
    /// Port used for the request.
    /// </summary>
    public string? Port { get; set; }

    /// <summary>
    /// Relative request URI.
    /// </summary>
    public string? RequestUri { get; set; }

    /// <summary>
    /// Request method.
    /// </summary>
    public string? RequestMethod { get; set; }

    /// <summary>
    /// Region of the host.
    /// </summary>
    public string? Region { get; set; }

    /// <summary>
    /// Geographical location of the host.
    /// </summary>
    public string? Geo { get; set; }
}
