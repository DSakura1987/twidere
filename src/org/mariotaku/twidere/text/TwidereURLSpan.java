package org.mariotaku.twidere.text;

import android.text.TextPaint;
import android.text.style.URLSpan;
import android.view.View;

import org.mariotaku.twidere.Constants;
import org.mariotaku.twidere.util.TwidereLinkify.OnLinkClickListener;

public class TwidereURLSpan extends URLSpan implements Constants {

	private final int type, highlightStyle, highlightColor;
	private final long account_id;
	private final String url, orig;
	private final boolean sensitive;
	private final OnLinkClickListener listener;

	public TwidereURLSpan(final String url, final long account_id, final int type, final boolean sensitive,
			final OnLinkClickListener listener, final int highlightStyle, final int highlightColor) {
		this(url, null, account_id, type, sensitive, listener, highlightStyle, highlightColor);
	}

	public TwidereURLSpan(final String url, final String orig, final long account_id, final int type,
			final boolean sensitive, final OnLinkClickListener listener, final int highlightStyle,
			final int highlightColor) {
		super(url);
		this.url = url;
		this.orig = orig;
		this.account_id = account_id;
		this.type = type;
		this.sensitive = sensitive;
		this.listener = listener;
		this.highlightStyle = highlightStyle;
		this.highlightColor = highlightColor;
	}

	@Override
	public void onClick(final View widget) {
		if (listener != null) {
			listener.onLinkClick(url, orig, account_id, type, sensitive);
		}
	}

	@Override
	public void updateDrawState(final TextPaint ds) {
		if ((highlightStyle & LINK_HIGHLIGHT_OPTION_CODE_UNDERLINE) != 0) {
			ds.setUnderlineText(true);
		}
		if ((highlightStyle & LINK_HIGHLIGHT_OPTION_CODE_HIGHLIGHT) != 0) {
			ds.setColor(highlightColor != 0 ? highlightColor : ds.linkColor);
		}
	}
}