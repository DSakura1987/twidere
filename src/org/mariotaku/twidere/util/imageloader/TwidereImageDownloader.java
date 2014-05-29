/*
 * 				Twidere - Twitter client for Android
 * 
 *  Copyright (C) 2012-2014 Mariotaku Lee <mariotaku.lee@gmail.com>
 * 
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.mariotaku.twidere.util.imageloader;

import static org.mariotaku.twidere.util.TwidereLinkify.PATTERN_TWITTER_PROFILE_IMAGES;
import static org.mariotaku.twidere.util.Utils.getImageLoaderHttpClient;
import static org.mariotaku.twidere.util.Utils.getNormalTwitterProfileImage;
import static org.mariotaku.twidere.util.Utils.getRedirectedHttpResponse;
import static org.mariotaku.twidere.util.Utils.getTwitterAuthorization;
import static org.mariotaku.twidere.util.Utils.getTwitterProfileImageOfSize;
import static org.mariotaku.twidere.util.Utils.replaceLast;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;

import com.nostra13.universalimageloader.core.assist.ContentLengthInputStream;
import com.nostra13.universalimageloader.core.download.BaseImageDownloader;

import org.mariotaku.twidere.Constants;
import org.mariotaku.twidere.R;
import org.mariotaku.twidere.model.ParcelableMedia;
import org.mariotaku.twidere.util.MediaPreviewUtils;

import twitter4j.TwitterException;
import twitter4j.auth.Authorization;
import twitter4j.http.HttpClientWrapper;
import twitter4j.http.HttpResponse;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Locale;
import java.util.regex.Pattern;

public class TwidereImageDownloader extends BaseImageDownloader implements Constants {

	private final Context mContext;
	private final SharedPreferences mPreferences;
	private HttpClientWrapper mClient;
	private boolean mFastImageLoading;
	private final boolean mFullImage;
	private final String mTwitterProfileImageSize;

	public TwidereImageDownloader(final Context context, final boolean fullImage) {
		super(context);
		mContext = context;
		mPreferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
		mFullImage = fullImage;
		mTwitterProfileImageSize = context.getString(R.string.profile_image_size);
		reloadConnectivitySettings();
	}

	public void reloadConnectivitySettings() {
		mClient = getImageLoaderHttpClient(mContext);
		mFastImageLoading = mContext.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE).getBoolean(
				KEY_FAST_IMAGE_LOADING, true);
	}

	@Override
	protected InputStream getStreamFromNetwork(final String uriString, final Object extras) throws IOException {
		if (uriString == null) return null;
		final ParcelableMedia media = MediaPreviewUtils.getAllAvailableImage(uriString, mFullImage, mFullImage
				|| !mFastImageLoading ? mClient : null);
		try {
			final String mediaUrl = media != null ? media.media_url : uriString;
			if (isTwitterProfileImage(uriString)) {
				final String replaced = getTwitterProfileImageOfSize(mediaUrl, mTwitterProfileImageSize);
				return getStreamFromNetworkInternal(replaced, extras);
			} else
				return getStreamFromNetworkInternal(mediaUrl, extras);
		} catch (final TwitterException e) {
			final int statusCode = e.getStatusCode();
			if (statusCode != -1 && isTwitterProfileImage(uriString) && !uriString.contains("_normal.")) {
				try {
					return getStreamFromNetworkInternal(getNormalTwitterProfileImage(uriString), extras);
				} catch (final TwitterException e2) {

				}
			}
			throw new IOException(String.format(Locale.US, "Error downloading image %s, error code: %d", uriString,
					statusCode));
		}
	}

	private String getReplacedTwitterHost(final String host) {
		if (host == null || !host.endsWith("twitter.com")) return host;
		final String jtapiHostname = mPreferences.getString(KEY_JTAPI_HOSTNAME, null);
		if (TextUtils.isEmpty(jtapiHostname)) return host;
		return replaceLast(host, "twitter\\.com", jtapiHostname);
	}

	private String getReplacedUri(final String uri, final String scheme, final String host) {
		final String replacedHost = getReplacedTwitterHost(host);
		final String target = Pattern.quote(String.format("%s://%s", scheme, host));
		return uri.replaceFirst(target, String.format("%s://%s", scheme, replacedHost));
	}

	private ContentLengthInputStream getStreamFromNetworkInternal(final String uriString, final Object extras)
			throws IOException, TwitterException {
		final URL url = new URL(uriString);
		final Authorization auth;
		if (isOAuthRequired(url) && extras instanceof AccountExtra) {
			final AccountExtra accountExtra = (AccountExtra) extras;
			auth = getTwitterAuthorization(mContext, accountExtra.account_id);
		} else {
			auth = null;
		}
		final String modifiedUri = getReplacedUri(uriString, url.getProtocol(), url.getHost());
		final HttpResponse resp = getRedirectedHttpResponse(mClient, modifiedUri, uriString, auth);
		return new ContentLengthInputStream(resp.asStream(), (int) resp.getContentLength());
	}

	private boolean isOAuthRequired(final URL url) {
		if (url == null) return false;
		return "ton.twitter.com".equalsIgnoreCase(url.getHost());
	}

	private boolean isTwitterProfileImage(final String uriString) {
		if (TextUtils.isEmpty(uriString)) return false;
		return PATTERN_TWITTER_PROFILE_IMAGES.matcher(uriString).matches();
	}

}
