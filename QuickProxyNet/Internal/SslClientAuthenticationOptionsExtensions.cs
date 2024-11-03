﻿using System.Collections;
using System.Diagnostics;
using System.Net.Security;
using System.Reflection;

namespace QuickProxyNet;

internal static class SslClientAuthenticationOptionsExtensions
{
    public static SslClientAuthenticationOptions ShallowClone(this SslClientAuthenticationOptions options)
    {
        // Use non-default values to verify the clone works fine.
        var clone = new SslClientAuthenticationOptions
        {
            AllowRenegotiation = options.AllowRenegotiation,
            AllowTlsResume = options.AllowTlsResume,
            ApplicationProtocols = options.ApplicationProtocols != null
                ? new List<SslApplicationProtocol>(options.ApplicationProtocols)
                : null,
            CertificateRevocationCheckMode = options.CertificateRevocationCheckMode,
            CertificateChainPolicy = options.CertificateChainPolicy,
            CipherSuitesPolicy = options.CipherSuitesPolicy,
            ClientCertificates = options.ClientCertificates,
            ClientCertificateContext = options.ClientCertificateContext,
            EnabledSslProtocols = options.EnabledSslProtocols,
            EncryptionPolicy = options.EncryptionPolicy,
            LocalCertificateSelectionCallback = options.LocalCertificateSelectionCallback,
            RemoteCertificateValidationCallback = options.RemoteCertificateValidationCallback,
            TargetHost = options.TargetHost
        };

#if DEBUG
        // Try to detect if a property gets added that we're not copying correctly.
        // The property count is guard for new properties that also needs to be added above.
        var properties =
            typeof(SslClientAuthenticationOptions).GetProperties(BindingFlags.Public | BindingFlags.Instance |
                                                                 BindingFlags.DeclaredOnly)!;
        Debug.Assert(properties.Length == 13);
        foreach (var pi in properties)
        {
            var origValue = pi.GetValue(options);
            var cloneValue = pi.GetValue(clone);

            if (origValue is IEnumerable origEnumerable)
            {
                var cloneEnumerable = cloneValue as IEnumerable;
                Debug.Assert(cloneEnumerable != null, $"{pi.Name}. Expected enumerable cloned value.");

                var e1 = origEnumerable.GetEnumerator();
                try
                {
                    var e2 = cloneEnumerable.GetEnumerator();
                    try
                    {
                        while (e1.MoveNext())
                        {
                            Debug.Assert(e2.MoveNext(), $"{pi.Name}. Cloned enumerator too short.");
                            Debug.Assert(Equals(e1.Current, e2.Current),
                                $"{pi.Name}. Cloned enumerator's values don't match.");
                        }

                        Debug.Assert(!e2.MoveNext(), $"{pi.Name}. Cloned enumerator too long.");
                    }
                    finally
                    {
                        (e2 as IDisposable)?.Dispose();
                    }
                }
                finally
                {
                    (e1 as IDisposable)?.Dispose();
                }
            }
            else
            {
                Debug.Assert(Equals(origValue, cloneValue), $"{pi.Name}. Expected: {origValue}, Actual: {cloneValue}");
            }
        }
#endif

        return clone;
    }
}