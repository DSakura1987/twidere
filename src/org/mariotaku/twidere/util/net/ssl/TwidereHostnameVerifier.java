package org.mariotaku.twidere.util.net.ssl;

import android.content.Context;

import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;

public class TwidereHostnameVerifier extends AbstractCheckSignatureVerifier {

	private final Context context;
	private final boolean ignoreSSLErrors;

	public TwidereHostnameVerifier(final Context context, final boolean ignoreSSLErrors) {
		this.context = context;
		this.ignoreSSLErrors = ignoreSSLErrors;
	}

	@Override
	public void verify(final String host, final String[] cns, final String[] subjectAlts, final X509Certificate cert)
			throws SSLException {
		if (host.endsWith(".appspot.com")) return;
		if (!verify(host, cns, subjectAlts, false)) throw new SSLException(String.format("Unable to verify %s", host));
	}

}
