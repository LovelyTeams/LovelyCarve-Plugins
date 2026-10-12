/*
 * LovelyCarve plugin C ABI, version 1.
 *
 * A plugin is a native library (.dll / .so / .dylib) next to its plugin.toml
 * that exports lovelycarve_plugin_v1. The host passes its function table and
 * receives the plugin's. The same library runs inside lc-plugin-host
 * (isolation = "process", the default) or directly in LovelyCarve
 * (isolation = "in_process").
 *
 * Every payload is MessagePack. A call names an LPP v1 method
 * (docs/PLUGIN_PROTOCOL.md) and carries that method's params; an
 * LC_STATUS_OK reply carries the method's result and an LC_STATUS_ERROR reply
 * a {code, message} map.
 *
 * Ownership: a reply buffer is filled by the callee and released by the caller
 * through the callee's free_buffer, so each side frees memory with its own
 * allocator. Threading: every function may be called concurrently from any
 * thread; a plugin call blocks until it returns, and cancellation is
 * cooperative (cancel asks a running call to return CANCELLED).
 *
 * The Rust SDK in plugins/sdk (crate lovelycarve-plugin) implements this
 * interface; abi.rs there is the reference definition.
 */
#ifndef LOVELYCARVE_PLUGIN_H
#define LOVELYCARVE_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LC_ABI_VERSION 1u

#define LC_STATUS_OK 0               /* reply holds the MessagePack result */
#define LC_STATUS_ERROR 1            /* reply holds a {code, message} map */
#define LC_STATUS_INVALID_ARGUMENT 2 /* null pointer or invalid payload */
#define LC_STATUS_ABI_MISMATCH 3     /* unsupported table version or size */
#define LC_STATUS_PANIC 4            /* the callee failed internally */

#define LC_LOG_ERROR 1u
#define LC_LOG_WARN 2u
#define LC_LOG_INFO 3u
#define LC_LOG_DEBUG 4u

/* Borrowed bytes, valid only for the duration of the call that receives them. */
typedef struct lc_bytes {
    const uint8_t *data;
    size_t len;
} lc_bytes;

/* Reply bytes, owned by the side that filled them. */
typedef struct lc_buffer {
    uint8_t *data;
    size_t len;
    size_t capacity;
} lc_buffer;

/* Functions the host offers to one plugin instance. The table and context
 * stay valid for as long as the instance exists. */
typedef struct lc_host_api_v1 {
    uint32_t abi_version; /* LC_ABI_VERSION */
    uint32_t struct_size; /* sizeof(lc_host_api_v1) */
    void *context;
    /* Plugin -> host LPP call: source.*, file.*, evidence.*, host.progress. */
    int32_t (*call)(void *context, lc_bytes method, lc_bytes params, lc_buffer *out);
    /* Releases a reply filled by call. */
    void (*free_buffer)(void *context, lc_buffer *buffer);
    /* Writes one UTF-8 line to the LovelyCarve log (LC_LOG_* level). */
    void (*log)(void *context, uint32_t level, lc_bytes message);
} lc_host_api_v1;

/* Functions of one plugin instance, filled in by the entry point. */
typedef struct lc_plugin_api_v1 {
    uint32_t abi_version; /* LC_ABI_VERSION */
    uint32_t struct_size; /* sizeof(lc_plugin_api_v1) */
    void *instance;
    /* plugin.hello params: {protocol_min, protocol_max,
     * plugin: {id, name, version}, capabilities: [...]}. */
    int32_t (*describe)(void *instance, lc_buffer *out);
    /* Host -> plugin LPP call: fs.*, analyzer.*, plugin.shutdown. call_id is
     * unique among in-flight calls. */
    int32_t (*call)(void *instance, uint64_t call_id, lc_bytes method, lc_bytes params,
                    lc_buffer *out);
    /* Asks the in-flight call call_id to return CANCELLED promptly. */
    void (*cancel)(void *instance, uint64_t call_id);
    /* Releases a reply filled by describe or call. */
    void (*free_buffer)(void *instance, lc_buffer *buffer);
    /* Releases the instance; the host calls it only when no call is in flight. */
    void (*destroy)(void *instance);
} lc_plugin_api_v1;

/* Creates an instance bound to host and writes its table to plugin; returns
 * LC_STATUS_OK or an error status (plugin is written only on success). May be
 * called again to create independent instances: instances must not share
 * process-global state. */
typedef int32_t (*lc_plugin_entry_v1)(const lc_host_api_v1 *host, lc_plugin_api_v1 *plugin);

#if defined(_WIN32)
#define LC_PLUGIN_EXPORT __declspec(dllexport)
#else
#define LC_PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

LC_PLUGIN_EXPORT int32_t lovelycarve_plugin_v1(const lc_host_api_v1 *host,
                                               lc_plugin_api_v1 *plugin);

#ifdef __cplusplus
}
#endif

#endif /* LOVELYCARVE_PLUGIN_H */
