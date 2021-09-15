package org.bouncycastle.crypto.tls;

import javabc.SecureRandom;

public interface TlsClientContext
{
    SecureRandom getSecureRandom();

    SecurityParameters getSecurityParameters();

    ProtocolVersion getClientVersion();

    ProtocolVersion getServerVersion();

    Object getUserObject();

    void setUserObject(Object userObject);
}
