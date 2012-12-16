/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.mariotaku.gallery3d.app;

import org.mariotaku.gallery3d.data.DataManager;
import org.mariotaku.gallery3d.data.DownloadCache;
import org.mariotaku.gallery3d.data.ImageCacheService;
import org.mariotaku.gallery3d.util.ThreadPool;

import android.content.ContentResolver;
import android.content.Context;
import android.content.res.Resources;
import android.os.Looper;

public interface IGalleryApplication {
	public Context getAndroidContext();

	public ContentResolver getContentResolver();

	public DataManager getDataManager();

	public DownloadCache getDownloadCache();

	public ImageCacheService getImageCacheService();

	public Looper getMainLooper();

	public Resources getResources();

	public ThreadPool getThreadPool();
}
