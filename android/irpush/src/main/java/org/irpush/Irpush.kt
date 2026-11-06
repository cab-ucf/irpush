package org.irpush

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.PowerManager
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.concurrent.thread

private const val ATTACH = "org.irpush.ATTACH"
private const val WAKE = "org.irpush.WAKE"
private const val HELLO = 1
private const val ID = 2
private const val PUSH = 3
private const val JOIN = 4
private const val JOINED = 5

/** In the app's own native library: it links the irpush crate with feature `jni`. */
internal object Native {
    init { System.loadLibrary(Irpush.lib) }
    @JvmStatic external fun start(path: String, kek: ByteArray, ticket: String?): String?
    @JvmStatic external fun next(): ByteArray
    @JvmStatic external fun has(host: String): Boolean
    @JvmStatic external fun app(name: String): ByteArray
    @JvmStatic external fun network(id: Long)
    @JvmStatic external fun kick(): Long
}

private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
private val main = Handler(Looper.getMainLooper())

/** The owner: the irpush app signed by this app's key that was installed
 *  first (the same answer in every app of the group). An app signed by
 *  another key is never trusted with this app's pushes. */
internal fun owner(ctx: Context): ComponentName? {
    val pm = ctx.packageManager
    return pm.queryIntentServices(Intent(ATTACH), 0).map { it.serviceInfo }
        .filter { pm.checkSignatures(ctx.packageName, it.packageName) == PackageManager.SIGNATURE_MATCH }
        .minWithOrNull(compareBy({ pm.getPackageInfo(it.packageName, 0).firstInstallTime }, { it.packageName }))
        ?.let { ComponentName(it.packageName, it.name) }
}

/**
 * One irpush connection per phone, shared by every app that includes this
 * library. Call [start] in `Application.onCreate`; pushes for this package
 * arrive in its callback, also when a push wakes the app.
 */
object Irpush {
    /** This phone's device id: what hosts push to. "" not joined, null not known yet. */
    @Volatile var id: String? = null
        private set
    internal var lib = "irpush"
    private var onPush: ((String, ByteArray) -> Unit)? = null
    private var onId: (String) -> Unit = {}
    private var joined: (Boolean) -> Unit = {}
    private lateinit var app: Context
    private var to: Messenger? = null
    private var bound: ComponentName? = null

    /** From the owner. A message missing its extras, or failing to
     *  unparcel, is ignored: never a crash. */
    private val me = Messenger(Handler(Looper.getMainLooper()) { m ->
        runCatching {
            val b = m.data
            when (m.what) {
                ID -> b.getString("id")?.let { id = it; if (it.isNotEmpty()) up(); onId(it) }
                PUSH -> b.getString("from")?.let { from -> b.getByteArray("d")?.let { onPush?.invoke(from, it) } }
                JOINED -> joined(b.getBoolean("ok")).also { joined = {} }
            }
        }
        true
    })

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(n: ComponentName, b: IBinder) {
            to = Messenger(b)
            send(HELLO, Bundle())
        }
        override fun onServiceDisconnected(n: ComponentName) { to = null; id = null }
        override fun onBindingDied(n: ComponentName) = reconnect()
        override fun onNullBinding(n: ComponentName) = reconnect()
    }

    /** [lib]: the app's native library that links irpush (feature `jni`).
     *  [onId]: the device id, whenever it is learnt ("" until joined). */
    fun start(ctx: Context, lib: String, onId: (String) -> Unit = {}, onPush: (from: String, data: ByteArray) -> Unit) {
        app = ctx.applicationContext
        this.lib = lib
        this.onId = onId
        this.onPush = onPush
        connect()
    }

    /** Join a host's mesh with its ticket (also when already in another);
     *  [done] says whether its host answered. */
    fun join(ticket: String, done: (Boolean) -> Unit = {}) = main.post {
        joined = done
        send(JOIN, Bundle().apply { putString("t", ticket) })
    }

    internal fun connect() = main.post {
        if (!::app.isInitialized || bound != null) return@post
        val c = owner(app) ?: return@post
        if (app.bindService(Intent(ATTACH).setComponent(c), conn, Context.BIND_AUTO_CREATE)) bound = c
    }

    private fun reconnect() {
        runCatching { app.unbindService(conn) }
        to = null; id = null; bound = null
        main.postDelayed({ connect() }, 1000)
    }

    /** Joined: keep the owner in the foreground (allowed while this app is). */
    private fun up() {
        val c = bound ?: return
        runCatching { app.startForegroundService(Intent(ATTACH).setComponent(c)) }
    }

    private fun send(what: Int, b: Bundle) = main.post {
        runCatching { to?.send(Message.obtain(null, what).apply { data = b; replyTo = me }) }
    }
}

/** The owner's state, one per process: the node, attached apps, held pushes. */
private object Hub {
    lateinit var ctx: Context
    var id: String? = null
    val clients = HashMap<String, Messenger>()
    val held = HashMap<String, ArrayDeque<Bundle>>()
    val me by lazy { Messenger(Handler(Looper.getMainLooper()) { m -> runCatching { handle(m) }; true }) }

    fun open(ticket: String?) {
        val was = id
        id = Native.start(File(ctx.filesDir, "irpush.state").path, kek(ctx), ticket) ?: return
        if (was != null) return
        ctx.getSystemService(ConnectivityManager::class.java)
            .registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
                override fun onLinkPropertiesChanged(n: Network, lp: LinkProperties) =
                    Native.network("${lp.interfaceName}${lp.dnsServers}".hashCode().toLong() and 0xffffffffL)
                override fun onLost(n: Network) = Native.network(-1)
            })
        thread(isDaemon = true, name = "irpush") {
            while (true) Native.next().let { f ->
                main.post { route(f.copyOfRange(32, 48).hex(), Bundle().apply {
                    putString("from", f.copyOfRange(0, 32).hex())
                    putByteArray("d", f.copyOfRange(48, f.size))
                }) }
            }
        }
        kick(ctx)
        runCatching { ctx.startForegroundService(Intent(ctx, Broker::class.java)) }
    }

    fun handle(m: Message) {
        val r = m.replyTo ?: return
        if (m.what == JOIN) m.data.getString("t")?.takeIf { it.length > 72 }?.let { open(it); wait(it.substring(8, 72), r, 120) }
        // Authenticated by the kernel: the calling uid's packages, and only theirs.
        for (a in ctx.packageManager.getPackagesForUid(m.sendingUid).orEmpty().map { Native.app(it).hex() }) {
            clients[a] = r
            held.remove(a)?.forEach { route(a, it) }
        }
        runCatching { r.send(Message.obtain(null, ID).apply { data = Bundle().apply { putString("id", id ?: "") } }) }
    }

    /** Until the ticket's host answers (or a minute): tell the joining app. */
    private fun wait(host: String, r: Messenger, n: Int) {
        val ok = id != null && Native.has(host)
        if (!ok && n > 0) { main.postDelayed({ wait(host, r, n - 1) }, 500); return }
        runCatching { r.send(Message.obtain(null, JOINED).apply { data = Bundle().apply { putBoolean("ok", ok) } }) }
    }

    fun route(app: String, b: Bundle) {
        val ok = clients[app]?.let { runCatching { it.send(Message.obtain(null, PUSH).apply { data = b }) }.isSuccess } == true
        if (ok) return
        clients.remove(app)
        held.getOrPut(app) { ArrayDeque() }.apply { if (size == 64) removeFirst(); addLast(b) }
        ctx.packageManager.queryIntentServices(Intent(ATTACH), 0).map { it.serviceInfo.packageName }
            .filter { Native.app(it).hex() == app }
            .forEach { ctx.sendBroadcast(Intent(WAKE).setComponent(ComponentName(it, Wake::class.java.name))
                .addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)) }
    }
}

/** The owner's service: binds apps to [Hub], and keeps it in the foreground once joined. */
class Broker : Service() {
    override fun onBind(i: Intent): IBinder = Hub.me.binder

    override fun onCreate() {
        super.onCreate()
        Hub.ctx = applicationContext
        Hub.open(null)
    }

    override fun onStartCommand(i: Intent?, f: Int, sid: Int): Int {
        val ch = "irpush".also {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(it, "Push connection", NotificationManager.IMPORTANCE_MIN))
        }
        val n = Notification.Builder(this, ch).setSmallIcon(applicationInfo.icon)
            .setContentTitle("Push connection for your apps").build()
        runCatching {
            if (Build.VERSION.SDK_INT >= 34)
                startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
            else startForeground(1, n)
        }
        if (Hub.id == null) { stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(sid) }
        return START_STICKY
    }
}

/** Heartbeat alarms (learned interval, inexact); owner restart after boot or update. */
class Alarm : BroadcastReceiver() {
    override fun onReceive(ctx: Context, i: Intent) {
        if (i.action == null) {
            ctx.getSystemService(PowerManager::class.java)
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "irpush:kick").acquire(10_000)
            kick(ctx)
        } else if (owner(ctx)?.packageName == ctx.packageName && File(ctx.filesDir, "irpush.state").exists())
            ctx.startForegroundService(Intent(ctx, Broker::class.java))
    }
}

/** The owner holds a push for this app: attach and fetch it. Spoofed, it fetches nothing. */
class Wake : BroadcastReceiver() {
    override fun onReceive(ctx: Context, i: Intent) {
        val p = goAsync()
        Irpush.connect()
        main.postDelayed({ p.finish() }, 9000)
    }
}

internal fun kick(ctx: Context) {
    val s = Native.kick().takeIf { it > 0 } ?: return
    ctx.getSystemService(AlarmManager::class.java).setAndAllowWhileIdle(
        AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + s * 1000,
        PendingIntent.getBroadcast(ctx, 0, Intent(ctx, Alarm::class.java), PendingIntent.FLAG_IMMUTABLE))
}

/** 32 random bytes for the node's state, wrapped by an Android Keystore key. */
private fun kek(ctx: Context): ByteArray {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val key = ks.getKey("irpush", null) as SecretKey? ?: KeyGenerator
        .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder("irpush",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    val f = File(ctx.filesDir, "irpush.kek")
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    if (f.exists()) f.readBytes().let {
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, it, 0, 12))
        return c.doFinal(it, 12, it.size - 12)
    }
    return ByteArray(32).also(SecureRandom()::nextBytes).also {
        c.init(Cipher.ENCRYPT_MODE, key)
        f.writeBytes(c.iv + c.doFinal(it))
    }
}
