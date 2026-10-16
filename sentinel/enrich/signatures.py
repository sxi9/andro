"""Code signatures: which third-party SDKs live inside an APK.

Two tables of Java package prefixes, Exodus-Privacy style: TRACKERS (the
analytics / ads / crash / profiling / location / push SDKs people want to
know about) and LIBRARIES (common, benign frameworks, so the scan can say
"this is a Flutter app with OkHttp" too). A class matches a signature when
its dotted name equals the prefix or starts with "<prefix>.".

match_prefixes() handles ~100k class names per APK, so it looks up each
class by its first one or two dotted segments instead of trying every
prefix (a few hundred) against every class.
"""
from __future__ import annotations

from typing import Iterable

CATEGORIES = ("analytics", "advertisement", "crash reporting", "profiling",
              "identification", "location", "push")


def _t(name: str, category: str, website: str, *signatures: str) -> dict:
    return {"name": name, "category": category, "website": website,
            "signatures": list(signatures)}


def _l(name: str, website: str, *signatures: str) -> dict:
    return {"name": name, "website": website, "signatures": list(signatures)}


TRACKERS: list[dict] = [
    # Google
    _t("Google Firebase Analytics", "analytics", "https://firebase.google.com/",
       "com.google.firebase.analytics", "com.google.android.gms.measurement"),
    _t("Google Analytics", "analytics", "https://analytics.google.com/",
       "com.google.android.gms.analytics", "com.google.analytics.tracking"),
    _t("Google AdMob", "advertisement", "https://admob.google.com/",
       "com.google.android.gms.ads", "com.google.ads"),
    _t("Google Ad Manager (DoubleClick)", "advertisement", "https://admanager.google.com/",
       "com.google.android.gms.ads.doubleclick", "com.google.android.gms.ads.admanager"),
    _t("Google Tag Manager", "analytics", "https://tagmanager.google.com/",
       "com.google.tagmanager", "com.google.android.gms.tagmanager"),
    _t("Google CrashLytics", "crash reporting", "https://firebase.google.com/products/crashlytics",
       "com.google.firebase.crashlytics", "com.crashlytics", "io.fabric.sdk.android"),
    _t("Google Firebase Performance", "profiling", "https://firebase.google.com/products/performance",
       "com.google.firebase.perf"),
    _t("Google Play Install Referrer", "analytics", "https://developer.android.com/google/play/installreferrer",
       "com.android.installreferrer"),
    # Meta
    _t("Facebook Analytics", "analytics", "https://developers.facebook.com/",
       "com.facebook.appevents"),
    _t("Facebook Audience Network", "advertisement", "https://www.facebook.com/audiencenetwork",
       "com.facebook.ads", "com.facebook.audiencenetwork"),
    _t("Facebook Login", "identification", "https://developers.facebook.com/docs/facebook-login",
       "com.facebook.login"),
    _t("Facebook Share", "identification", "https://developers.facebook.com/docs/sharing",
       "com.facebook.share"),
    _t("Facebook Places", "location", "https://developers.facebook.com/docs/places",
       "com.facebook.places"),
    # attribution / product analytics
    _t("AppsFlyer", "analytics", "https://www.appsflyer.com/", "com.appsflyer"),
    _t("Adjust", "analytics", "https://www.adjust.com/", "com.adjust.sdk"),
    _t("Branch", "analytics", "https://branch.io/", "io.branch"),
    _t("Amplitude", "analytics", "https://amplitude.com/", "com.amplitude"),
    _t("Mixpanel", "analytics", "https://mixpanel.com/", "com.mixpanel.android"),
    _t("Segment", "analytics", "https://segment.com/", "com.segment.analytics"),
    _t("Flurry", "analytics", "https://www.flurry.com/", "com.flurry"),
    _t("Braze (Appboy)", "analytics", "https://www.braze.com/", "com.appboy", "com.braze"),
    _t("CleverTap", "analytics", "https://clevertap.com/", "com.clevertap.android"),
    _t("MoEngage", "analytics", "https://www.moengage.com/", "com.moengage", "com.moe.pushlibrary"),
    _t("Leanplum", "analytics", "https://www.leanplum.com/", "com.leanplum"),
    _t("Kochava", "analytics", "https://www.kochava.com/", "com.kochava"),
    _t("Singular", "analytics", "https://www.singular.net/", "com.singular.sdk"),
    _t("Tune", "analytics", "https://www.tune.com/", "com.tune", "com.mobileapptracker"),
    _t("Localytics", "analytics", "https://www.localytics.com/",
       "com.localytics.android", "com.localytics.androidx"),
    _t("comScore", "analytics", "https://www.comscore.com/", "com.comscore"),
    _t("Nielsen", "analytics", "https://www.nielsen.com/", "com.nielsen.app.sdk"),
    _t("Adobe Experience Cloud", "analytics", "https://business.adobe.com/",
       "com.adobe.marketing.mobile", "com.adobe.mobile"),
    _t("Swrve", "analytics", "https://www.swrve.com/", "com.swrve.sdk"),
    _t("Iterable", "analytics", "https://iterable.com/", "com.iterable.iterableapi"),
    _t("Apptentive", "analytics", "https://www.apptentive.com/", "com.apptentive.android"),
    _t("Heap", "analytics", "https://heap.io/", "com.heapanalytics"),
    _t("Countly", "analytics", "https://countly.com/", "ly.count.android"),
    _t("Matomo (Piwik)", "analytics", "https://matomo.org/", "org.matomo.sdk", "org.piwik.sdk"),
    _t("Salesforce Marketing Cloud", "analytics", "https://www.salesforce.com/products/marketing-cloud/",
       "com.salesforce.marketingcloud", "com.exacttarget.etpushsdk"),
    _t("Marketo", "analytics", "https://www.marketo.com/", "com.marketo"),
    _t("Exponea (Bloomreach)", "analytics", "https://exponea.com/", "com.exponea.sdk"),
    _t("Treasure Data", "analytics", "https://www.treasuredata.com/", "com.treasuredata.android"),
    _t("Tenjin", "analytics", "https://www.tenjin.com/", "com.tenjin.android"),
    _t("GameAnalytics", "analytics", "https://gameanalytics.com/", "com.gameanalytics.sdk"),
    _t("Amazon Pinpoint", "analytics", "https://aws.amazon.com/pinpoint/",
       "com.amazonaws.mobileconnectors.pinpoint"),
    _t("Unity Analytics", "analytics", "https://unity.com/products/unity-analytics",
       "com.unity3d.services.analytics", "com.unity.services.analytics"),
    _t("TikTok Business SDK", "analytics", "https://ads.tiktok.com/",
       "com.tiktok.appevents", "com.tiktok.open", "com.bytedance.sdk.open.tiktok"),
    _t("Pinterest SDK", "analytics", "https://developers.pinterest.com/",
       "com.pinterest.pinit", "com.pinterest.sdk"),
    _t("Mapbox Telemetry", "location", "https://www.mapbox.com/",
       "com.mapbox.android.telemetry", "com.mapbox.mapboxsdk.telemetry"),
    # Asian ecosystems
    _t("Huawei HMS Analytics", "analytics", "https://developer.huawei.com/consumer/en/hms/huawei-analyticskit/",
       "com.huawei.hms.analytics", "com.huawei.hianalytics"),
    _t("Huawei Ads", "advertisement", "https://developer.huawei.com/consumer/en/hms/huawei-adskit/",
       "com.huawei.hms.ads", "com.huawei.openalliance.ad"),
    _t("Huawei Push", "push", "https://developer.huawei.com/consumer/en/hms/huawei-pushkit/",
       "com.huawei.hms.push"),
    _t("Umeng", "analytics", "https://www.umeng.com/", "com.umeng"),
    _t("Tencent Bugly", "crash reporting", "https://bugly.qq.com/", "com.tencent.bugly"),
    _t("Tencent MTA", "analytics", "https://mta.qq.com/", "com.tencent.stat", "com.tencent.mid"),
    _t("WeChat Open SDK", "identification", "https://open.weixin.qq.com/", "com.tencent.mm.opensdk"),
    _t("Baidu Mobile Stat", "analytics", "https://mtj.baidu.com/", "com.baidu.mobstat"),
    _t("Baidu Mobile Ads", "advertisement", "https://union.baidu.com/", "com.baidu.mobads"),
    _t("JPush (Aurora)", "push", "https://www.jiguang.cn/", "cn.jpush.android", "cn.jiguang"),
    _t("Getui", "push", "https://www.getui.com/", "com.igexin"),
    _t("Xiaomi Mi Push", "push", "https://dev.mi.com/console/appservice/push.html",
       "com.xiaomi.mipush", "com.xiaomi.push"),
    _t("Yandex AppMetrica", "analytics", "https://appmetrica.yandex.com/",
       "com.yandex.metrica", "io.appmetrica.analytics"),
    _t("Yandex Mobile Ads", "advertisement", "https://yandex.com/dev/mobile-ads/",
       "com.yandex.mobile.ads"),
    _t("VK SDK", "identification", "https://dev.vk.com/", "com.vk.sdk", "com.vk.api.sdk"),
    _t("myTarget (VK Ads)", "advertisement", "https://target.my.com/", "com.my.target"),
    # ad networks / mediation
    _t("Unity Ads", "advertisement", "https://unity.com/products/unity-ads",
       "com.unity3d.ads", "com.unity3d.services"),
    _t("AppLovin (MAX)", "advertisement", "https://www.applovin.com/", "com.applovin"),
    _t("ironSource", "advertisement", "https://www.is.com/", "com.ironsource"),
    _t("Supersonic", "advertisement", "https://www.is.com/", "com.supersonic", "com.supersonicads"),
    _t("Vungle (Liftoff)", "advertisement", "https://vungle.com/", "com.vungle"),
    _t("Chartboost", "advertisement", "https://www.chartboost.com/", "com.chartboost.sdk"),
    _t("MoPub", "advertisement", "https://www.mopub.com/", "com.mopub"),
    _t("Tapjoy", "advertisement", "https://www.tapjoy.com/", "com.tapjoy"),
    _t("InMobi", "advertisement", "https://www.inmobi.com/", "com.inmobi"),
    _t("Pangle (ByteDance)", "advertisement", "https://www.pangleglobal.com/",
       "com.bytedance.sdk.openadsdk", "com.pangle"),
    _t("Mintegral", "advertisement", "https://www.mintegral.com/",
       "com.mbridge.msdk", "com.mintegral.msdk"),
    _t("Start.io (StartApp)", "advertisement", "https://www.start.io/", "com.startapp"),
    _t("Smaato", "advertisement", "https://www.smaato.com/", "com.smaato"),
    _t("Fyber", "advertisement", "https://www.fyber.com/", "com.fyber"),
    _t("Digital Turbine", "advertisement", "https://www.digitalturbine.com/", "com.digitalturbine"),
    _t("AdColony", "advertisement", "https://www.adcolony.com/", "com.adcolony"),
    _t("PubMatic", "advertisement", "https://pubmatic.com/", "com.pubmatic.sdk"),
    _t("Criteo", "advertisement", "https://www.criteo.com/", "com.criteo"),
    _t("Taboola", "advertisement", "https://www.taboola.com/", "com.taboola"),
    _t("Outbrain", "advertisement", "https://www.outbrain.com/", "com.outbrain"),
    _t("Ogury", "advertisement", "https://ogury.com/", "io.presage", "com.ogury"),
    _t("Teads", "advertisement", "https://www.teads.com/", "tv.teads"),
    _t("Amazon Mobile Ads", "advertisement", "https://advertising.amazon.com/",
       "com.amazon.device.ads"),
    _t("Verizon Media (Millennial)", "advertisement", "https://www.yahooinc.com/",
       "com.millennialmedia", "com.verizon.ads", "com.yahoo.ads"),
    _t("HyprMX", "advertisement", "https://www.hyprmx.com/", "com.hyprmx"),
    _t("AppNext", "advertisement", "https://www.appnext.com/", "com.appnext"),
    _t("Appodeal", "advertisement", "https://appodeal.com/", "com.appodeal"),
    _t("Pollfish", "advertisement", "https://www.pollfish.com/", "com.pollfish"),
    _t("Tapdaq", "advertisement", "https://tapdaq.com/", "com.tapdaq"),
    _t("Adform", "advertisement", "https://site.adform.com/", "com.adform.sdk"),
    _t("BidMachine", "advertisement", "https://bidmachine.io/", "io.bidmachine"),
    _t("Kidoz", "advertisement", "https://kidoz.net/", "com.kidoz.sdk"),
    _t("Verve (PubNative)", "advertisement", "https://verve.com/", "net.pubnative"),
    _t("Moloco", "advertisement", "https://www.moloco.com/", "com.moloco.sdk"),
    _t("Moat (Oracle)", "advertisement", "https://www.oracle.com/cx/advertising/measure/",
       "com.moat.analytics"),
    _t("Integral Ad Science", "advertisement", "https://integralads.com/", "com.integralads"),
    # crash / performance / session replay
    _t("Bugsnag", "crash reporting", "https://www.bugsnag.com/", "com.bugsnag.android"),
    _t("Sentry", "crash reporting", "https://sentry.io/", "io.sentry"),
    _t("Microsoft App Center", "crash reporting", "https://appcenter.ms/", "com.microsoft.appcenter"),
    _t("HockeyApp", "crash reporting", "https://www.hockeyapp.net/", "net.hockeyapp.android"),
    _t("Instabug", "crash reporting", "https://instabug.com/", "com.instabug"),
    _t("Bugfender", "crash reporting", "https://bugfender.com/", "com.bugfender.sdk"),
    _t("Rollbar", "crash reporting", "https://rollbar.com/", "com.rollbar"),
    _t("Raygun", "crash reporting", "https://raygun.com/",
       "com.mindscapehq.android.raygun4android", "com.raygun.raygun4android"),
    _t("New Relic", "profiling", "https://newrelic.com/", "com.newrelic.agent.android"),
    _t("Datadog", "profiling", "https://www.datadoghq.com/", "com.datadog.android"),
    _t("Dynatrace", "profiling", "https://www.dynatrace.com/", "com.dynatrace.android"),
    _t("Embrace", "profiling", "https://embrace.io/", "io.embrace.android"),
    _t("FullStory", "profiling", "https://www.fullstory.com/", "com.fullstory"),
    _t("UXCam", "profiling", "https://uxcam.com/", "com.uxcam"),
    _t("Smartlook", "profiling", "https://www.smartlook.com/", "com.smartlook"),
    _t("Appsee", "profiling", "https://www.appsee.com/", "com.appsee"),
    _t("Contentsquare (Clicktale)", "profiling", "https://contentsquare.com/",
       "com.contentsquare.android", "com.clicktale"),
    _t("Medallia", "profiling", "https://www.medallia.com/", "com.medallia.digital"),
    # experimentation / feature flags
    _t("Apptimize", "profiling", "https://apptimize.com/", "com.apptimize"),
    _t("Optimizely", "profiling", "https://www.optimizely.com/", "com.optimizely"),
    _t("LaunchDarkly", "profiling", "https://launchdarkly.com/", "com.launchdarkly"),
    _t("Split", "profiling", "https://www.split.io/", "io.split"),
    # in-app support / messaging that profiles users
    _t("Intercom", "profiling", "https://www.intercom.com/", "io.intercom.android"),
    _t("Freshchat", "profiling", "https://www.freshworks.com/live-chat-software/",
       "com.freshchat.consumer.sdk"),
    _t("Helpshift", "profiling", "https://www.helpshift.com/", "com.helpshift"),
    # push / engagement
    _t("OneSignal", "push", "https://onesignal.com/", "com.onesignal"),
    _t("Airship (Urban Airship)", "push", "https://www.airship.com/", "com.urbanairship"),
    _t("Pushwoosh", "push", "https://www.pushwoosh.com/", "com.pushwoosh"),
    _t("Batch", "push", "https://batch.com/", "com.batch.android"),
    _t("Oracle Responsys", "push", "https://www.oracle.com/cx/marketing/", "com.oracle.cx.mobilesdk", "com.pushio.manager"),
    _t("Sailthru (Marigold)", "push", "https://www.meetmarigold.com/", "com.sailthru.mobile", "com.marigold.sdk"),
    _t("Emarsys", "push", "https://emarsys.com/", "com.emarsys"),
    # identity / social
    _t("Snap Kit", "identification", "https://kit.snapchat.com/", "com.snap.kit", "com.snapchat.kit"),
    _t("Twitter Kit", "identification", "https://developer.twitter.com/", "com.twitter.sdk.android"),
    _t("LinkedIn SDK", "identification", "https://www.linkedin.com/developers/", "com.linkedin.platform"),
    _t("Sift", "identification", "https://sift.com/", "siftscience.android", "com.sift.api"),
    # location data brokers
    _t("HERE SDK", "location", "https://developer.here.com/", "com.here.sdk", "com.here.android"),
    _t("Foursquare Pilgrim (Movement)", "location", "https://foursquare.com/",
       "com.foursquare.pilgrim", "com.foursquare.movement"),
    _t("Radar", "location", "https://radar.com/", "io.radar.sdk"),
    _t("Cuebiq", "location", "https://www.cuebiq.com/", "com.cuebiq.cuebiqsdk"),
    _t("X-Mode", "location", "https://xmode.io/", "io.mysdk", "io.xmode"),
    _t("Tutela", "location", "https://www.tutela.com/", "com.tutelatechnologies"),
    _t("OpenSignal", "location", "https://www.opensignal.com/", "com.opensignal"),
    _t("SafeGraph", "location", "https://www.safegraph.com/", "com.safegraph"),
    _t("inMarket", "location", "https://inmarket.com/", "com.inmarket"),
    _t("Placer", "location", "https://www.placer.ai/", "com.placer.client", "com.placer"),
]

LIBRARIES: list[dict] = [
    _l("OkHttp", "https://square.github.io/okhttp/", "okhttp3"),
    _l("Retrofit", "https://square.github.io/retrofit/", "retrofit2"),
    _l("Glide", "https://bumptech.github.io/glide/", "com.bumptech.glide"),
    _l("Picasso", "https://square.github.io/picasso/", "com.squareup.picasso"),
    _l("Fresco", "https://frescolib.org/", "com.facebook.fresco", "com.facebook.imagepipeline", "com.facebook.drawee"),
    _l("Gson", "https://github.com/google/gson", "com.google.gson"),
    _l("Moshi", "https://github.com/square/moshi", "com.squareup.moshi"),
    _l("Jackson", "https://github.com/FasterXML/jackson", "com.fasterxml.jackson"),
    _l("Room", "https://developer.android.com/jetpack/androidx/releases/room", "androidx.room"),
    _l("WorkManager", "https://developer.android.com/jetpack/androidx/releases/work", "androidx.work"),
    _l("Kotlin coroutines", "https://github.com/Kotlin/kotlinx.coroutines", "kotlinx.coroutines"),
    _l("RxJava", "https://github.com/ReactiveX/RxJava", "io.reactivex"),
    _l("Dagger / Hilt", "https://dagger.dev/", "dagger"),
    _l("Koin", "https://insert-koin.io/", "org.koin"),
    _l("Realm", "https://realm.io/", "io.realm"),
    _l("SQLCipher", "https://www.zetetic.net/sqlcipher/", "net.sqlcipher"),
    _l("Conscrypt", "https://www.conscrypt.org/", "org.conscrypt"),
    _l("Bouncy Castle", "https://www.bouncycastle.org/", "org.bouncycastle", "org.spongycastle"),
    _l("ExoPlayer / Media3", "https://developer.android.com/media/media3",
       "com.google.android.exoplayer2", "androidx.media3"),
    _l("Lottie", "https://airbnb.io/lottie/", "com.airbnb.lottie"),
    _l("Coil", "https://coil-kt.github.io/coil/", "coil"),
    _l("Timber", "https://github.com/JakeWharton/timber", "timber.log"),
    _l("Flutter", "https://flutter.dev/", "io.flutter"),
    _l("React Native", "https://reactnative.dev/", "com.facebook.react"),
    _l("Apache Cordova", "https://cordova.apache.org/", "org.apache.cordova"),
    _l("Xamarin / .NET", "https://dotnet.microsoft.com/apps/xamarin", "mono.android", "xamarin.android"),
    _l("Unity engine", "https://unity.com/", "com.unity3d.player"),
    _l("Unreal Engine", "https://www.unrealengine.com/", "com.epicgames"),
    _l("Godot", "https://godotengine.org/", "org.godotengine"),
    _l("Capacitor", "https://capacitorjs.com/", "com.getcapacitor"),
    _l("Ionic", "https://ionicframework.com/", "io.ionic"),
    _l("Chromium", "https://www.chromium.org/", "org.chromium"),
    _l("Jetpack Compose", "https://developer.android.com/jetpack/compose", "androidx.compose"),
    _l("Material Components", "https://material.io/develop/android", "com.google.android.material"),
    _l("Google Play Services (core)", "https://developers.google.com/android", "com.google.android.gms.common"),
    _l("Google Play Billing", "https://developer.android.com/google/play/billing", "com.android.billingclient"),
    _l("Firebase Cloud Messaging", "https://firebase.google.com/products/cloud-messaging",
       "com.google.firebase.messaging"),
    _l("Firebase Auth", "https://firebase.google.com/products/auth", "com.google.firebase.auth"),
    _l("Firebase Firestore", "https://firebase.google.com/products/firestore", "com.google.firebase.firestore"),
    _l("ZXing", "https://github.com/zxing/zxing", "com.google.zxing"),
    _l("ML Kit", "https://developers.google.com/ml-kit", "com.google.mlkit"),
    _l("TensorFlow Lite", "https://www.tensorflow.org/lite", "org.tensorflow.lite"),
    _l("Protocol Buffers", "https://protobuf.dev/", "com.google.protobuf"),
    _l("Ktor", "https://ktor.io/", "io.ktor"),
    _l("Apollo GraphQL", "https://www.apollographql.com/", "com.apollographql"),
    _l("Stripe", "https://stripe.com/", "com.stripe"),
    _l("Razorpay", "https://razorpay.com/", "com.razorpay"),
    _l("Paytm", "https://paytm.com/", "com.paytm"),
    _l("Braintree", "https://www.braintreepayments.com/", "com.braintreepayments"),
    _l("PayPal", "https://developer.paypal.com/", "com.paypal"),
]

TRACKER_BY_NAME: dict[str, dict] = {t["name"]: t for t in TRACKERS}
LIBRARY_BY_NAME: dict[str, dict] = {lib["name"]: lib for lib in LIBRARIES}


def _index(table: list[dict]) -> dict[str, list[tuple[str, str]]]:
    """{first one-or-two segments of a prefix: [(prefix, entry name)]}."""
    idx: dict[str, list[tuple[str, str]]] = {}
    for entry in table:
        for sig in entry["signatures"]:
            key = ".".join(sig.split(".")[:2])
            idx.setdefault(key, []).append((sig, entry["name"]))
    return idx


_INDEXES: dict[int, dict] = {}


def _index_for(table: list[dict]) -> dict:
    idx = _INDEXES.get(id(table))
    if idx is None:
        idx = _INDEXES[id(table)] = _index(table)
    return idx


def _hits(idx: dict, class_name: str) -> list[tuple[str, str]]:
    """(prefix, entry name) pairs the class belongs to; inner classes count
    for their outer class."""
    base = class_name.split("$", 1)[0]
    segs = base.split(".")
    cands = idx.get(segs[0], [])
    if len(segs) > 1:
        cands = cands + idx.get(segs[0] + "." + segs[1], [])
    return [(sig, name) for sig, name in cands if base == sig or base.startswith(sig + ".")]


def match_prefixes(class_names: Iterable[str], table: list[dict] | None = None
                   ) -> dict[str, dict]:
    """{entry name: {"signatures_matched": set, "classes": int}} for every
    tracker (or library, with table=LIBRARIES) whose prefixes occur in
    class_names. A class counts once per entry even when two of that
    entry's prefixes nest."""
    idx = _index_for(TRACKERS if table is None else table)
    out: dict[str, dict] = {}
    for cn in class_names:
        seen: set[str] = set()
        for sig, name in _hits(idx, cn):
            rec = out.get(name)
            if rec is None:
                rec = out[name] = {"signatures_matched": set(), "classes": 0}
            rec["signatures_matched"].add(sig)
            if name not in seen:
                seen.add(name)
                rec["classes"] += 1
    return out


def tracker_for_class(class_name: str) -> str | None:
    """Name of the tracker a single class (e.g. a manifest component) belongs
    to, or None. The longest matching prefix wins."""
    hits = _hits(_index_for(TRACKERS), class_name or "")
    if not hits:
        return None
    return max(hits, key=lambda h: len(h[0]))[1]
